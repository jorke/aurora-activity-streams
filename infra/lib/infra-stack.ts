import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as domain from 'aws-cdk-lib/aws-opensearchservice'
import * as path from 'path';
import { Domain } from 'aws-cdk-lib/aws-opensearchservice';
import { SubnetType } from 'aws-cdk-lib/aws-ec2';
import { Duration } from 'aws-cdk-lib';
import { Effect, Policy, PolicyStatement } from 'aws-cdk-lib/aws-iam';



export class InfraStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const vpc = new ec2.Vpc(this, 'vpc', {
      ipAddresses: ec2.IpAddresses.cidr('10.0.0.0/16'),
    });

    vpc.addInterfaceEndpoint('kmsendpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.KMS,
    });
    
    const sg = new ec2.SecurityGroup(this, 'intercom', {
      vpc,
      allowAllOutbound: true,
      description: 'internal comm',
    })
    
    sg.addIngressRule(
      sg,
      ec2.Port.allTraffic(),
      'all internal traffic'
    )

    const cluster = new rds.DatabaseCluster(this, 'db', {
      engine: rds.DatabaseClusterEngine.auroraPostgres({ version: rds.AuroraPostgresEngineVersion.VER_14_6}),
      credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
      instanceProps: { 
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.R6G, ec2.InstanceSize.LARGE),
        vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS, },
        vpc,
      },
    });

    const key = new kms.Key(this, 'key', {
      pendingWindow: cdk.Duration.days(10),
      keySpec: kms.KeySpec.SYMMETRIC_DEFAULT,
      keyUsage: kms.KeyUsage.ENCRYPT_DECRYPT
    })
    
    const keyPolicy = new iam.Policy(this, 'keypolicy', {
      statements: [
        new iam.PolicyStatement({
          resources: [key.keyArn],
          actions: [ 
            "kms:Decrypt",
            "kms:DescribeKey",
            "kms:Encrypt",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*"
          ],
          effect: iam.Effect.ALLOW,
        }),
      ]
    });

    const bucket = new s3.Bucket(this, 'bucket');
  
    new cdk.CfnOutput(this, 'bucketName', {
      value: bucket.bucketName,
      description: 's3 bucket'
    });

    const cfnCluster = cluster.node.defaultChild as rds.CfnDBCluster
    const clusterArn = cfnCluster.getAtt('DBClusterArn').toString()



    const role = new iam.Role(this, 'lambda-role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });
    
    role.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaBasicExecutionRole"));
    role.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaVPCAccessExecutionRole")); // only required if your function lives in a VPC
    role.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonKinesisReadOnlyAccess"))
    role.attachInlinePolicy(keyPolicy);

    const os = new Domain(this, 'domain', {
      version: cdk.aws_opensearchservice.EngineVersion.OPENSEARCH_2_3,
      ebs: {
        volumeSize: 100,
        volumeType: ec2.EbsDeviceVolumeType.GENERAL_PURPOSE_SSD_GP3
      },
      capacity: {
        dataNodes: 2,
      },
      nodeToNodeEncryption: true,
      encryptionAtRest: { enabled: true},
      vpc: vpc,
      securityGroups: [sg],
      zoneAwareness: {
        enabled: true,
      },
      accessPolicies: [
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ["*"],
          principals: [new iam.AnyPrincipal()],
          resources: [`arn:aws:es:${this.region}:${this.account}:domain/*/*`]
        })
      ]
      
    })


    const layer = new lambda.LayerVersion(this, 'layer', {
      code: lambda.Code.fromAsset(path.join(__dirname, '../../das-encryption-opensearch')),
      compatibleRuntimes: [lambda.Runtime.PYTHON_3_9],
      description: 'encryption libs + opensearch client',
    });

    const fn = new lambda.Function(this, 'das-opensearch', {
      runtime: lambda.Runtime.PYTHON_3_9,
      handler: 'index.main',
      code: lambda.Code.fromAsset(path.join(__dirname, '../../das-opensearch')),
      layers: [layer],
      vpc: vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS},
      securityGroups: [sg],
      environment: {
        "resource_id": cluster.clusterResourceIdentifier,
        "host": os.domainEndpoint,
      },
      timeout: Duration.seconds(120),
      role: role,
    })
    const jslayer = new lambda.LayerVersion(this, 'jslayer', {
      code: lambda.Code.fromAsset(path.join(__dirname, '../../js-layer/lib')),
      compatibleRuntimes: [lambda.Runtime.NODEJS_18_X],
      description: 'encryption libs + opensearch client',
    });

    const jsfn = new lambda.Function(this, 'js-das-opensearch', {
      runtime: lambda.Runtime.NODEJS_18_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../../js')),
      layers: [jslayer],
      vpc: vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS},
      securityGroups: [sg],
      environment: {
        "resource_id": cluster.clusterResourceIdentifier,
        "host": os.domainEndpoint,
      },
      timeout: Duration.seconds(120),
      role: role,
    })

    new cdk.CfnOutput(this, 'db-cluster', {
      value: clusterArn,
      description: 'RDS cluster'
    });

    new cdk.CfnOutput(this, 'kms-key', {
      value: key.keyArn,
      description: 'KMS key',
    });

    new cdk.CfnOutput(this, 'cmd', {
      value: `start-activity-stream --resource-arn ${clusterArn} --mode async --kms-key-id ${key.keyArn}`
    })

  }
}
