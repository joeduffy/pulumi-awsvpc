# AWS Virtual Private Cloud (VPC) Pulumi Package

This Pulumi Package provides a networking foundation based on AWS best practices for your AWS infrastructure. It builds
a Virtual Private Cloud (VPC) with public and private subnets where you can launch AWS services and other resources.

All resources are provisioned using Pulumi Infrastructure as Code. This package is inherently multi-language, meaning
versions are available in the following languages: any Node.js language (JavaScript, TypeScript, etc), Python, Go, or
any .NET language (C#, F#, etc).

## Prerequisites

* [Install Pulumi](https://www.pulumi.com/docs/get-started/install/)

## Using this Package

To use this package, first install it in your language of choice [instructions instructions in all languages TBD].

To create a VPC using this package, first create a Pulumi project and install the package in your language
of choice [instructions in all languages TBD]. In your program, instantiate the VPC [examples in all languages TBD]:

```typescript
import { Vpc } from "@pulumi/awsvpc";
export const vpc = new Vpc("my-vpc");
```

To deploy the VPC, first configure the AWS region you will deploy into:

```bash
$ pulumi config set aws:region us-west-2
```

And then run:

```bash
$ pulumi up
```

After the update finishes, many attributes about your new VPC will be output. Here is sample:

```
Updating (dev):
     Type                                     Name                                  Status
 +   pulumi:pulumi:Stack                      aws-base-dev                          created
 +   └─ awsvpc:index:Vpc:Vpc                  my-vpc                                created
 +      ├─ aws:ec2:Vpc                        VPC                                   created
 +      ├─ aws:ec2:VpcDhcpOptions             DHCPOptions                           created
 +      ├─ aws:ec2:VpcDhcpOptionsAssociation  VPCDHCPOptionsAssociation             created
 +      ├─ aws:ec2:InternetGateway            InternetGateway                       created
 +      ├─ aws:ec2:RouteTable                 PublicSubnetRouteTable                created
 +      ├─ aws:ec2:Subnet                     PublicSubnet2                         created
 +      ├─ aws:ec2:Subnet                     PrivateSubnet2A                       created
 +      ├─ aws:ec2:RouteTable                 PrivateSubnet1ARouteTable             created
 +      ├─ aws:ec2:Subnet                     PrivateSubnet0A                       created
 +      ├─ aws:ec2:Subnet                     PrivateSubnet1A                       created
 +      ├─ aws:ec2:RouteTable                 PrivateSubnet0ARouteTable             created
 +      ├─ aws:ec2:RouteTable                 PrivateSubnet3ARouteTable             created
 +      ├─ aws:ec2:Subnet                     PrivateSubnet3A                       created
 +      ├─ aws:ec2:Subnet                     PublicSubnet1                         created
 +      ├─ aws:ec2:RouteTable                 PrivateSubnet2ARouteTable             created
 +      ├─ aws:ec2:Subnet                     PublicSubnet3                         created
 +      ├─ aws:ec2:Subnet                     PublicSubnet0                         created
 +      ├─ aws:ec2:Eip                        NAT2EIP                               created
 +      ├─ aws:ec2:Eip                        NAT0EIP                               created
 +      ├─ aws:ec2:Eip                        NAT3EIP                               created
 +      ├─ aws:ec2:Eip                        NAT1EIP                               created
 +      ├─ aws:ec2:Route                      PublicSubnetRoute                     created
 +      ├─ aws:ec2:RouteTableAssociation      PublicSubnet2RouteTableAssociation    created
 +      ├─ aws:ec2:RouteTableAssociation      PrivateSubnet0ARouteTableAssociation  created
 +      ├─ aws:ec2:RouteTableAssociation      PrivateSubnet1ARouteTableAssociation  created
 +      ├─ aws:ec2:RouteTableAssociation      PrivateSubnet3ARouteTableAssociation  created
 +      ├─ aws:ec2:RouteTableAssociation      PrivateSubnet2ARouteTableAssociation  created
 +      ├─ aws:ec2:VpcEndpoint                S3VPCEndpoint                         created
 +      ├─ aws:ec2:RouteTableAssociation      PublicSubnet1RouteTableAssociation    created
 +      ├─ aws:ec2:RouteTableAssociation      PublicSubnet3RouteTableAssociation    created
 +      ├─ aws:ec2:RouteTableAssociation      PublicSubnet0RouteTableAssociation    created
 +      ├─ aws:ec2:NatGateway                 NATGateway2                           created
 +      ├─ aws:ec2:NatGateway                 NATGateway0                           created
 +      ├─ aws:ec2:NatGateway                 NATGateway3                           created
 +      ├─ aws:ec2:NatGateway                 NATGateway1                           created
 +      ├─ aws:ec2:Route                      PrivateSubnet3ARoute                  created
 +      ├─ aws:ec2:Route                      PrivateSubnet2ARoute                  created
 +      ├─ aws:ec2:Route                      PrivateSubnet1ARoute                  created
 +      └─ aws:ec2:Route                      PrivateSubnet0ARoute                  created

Outputs:
    vpc: {
        cidr                      : "10.0.0.0/16"
        id                        : "vpc-0783c2432995b1ab2"
        natEips                   : [
            [0]: "35.155.49.242"
            [1]: "54.189.86.132"
            [2]: "44.231.41.106"
            [3]: "54.185.180.161"
        ]
        privateSubnetCidrs        : [
            [0]: "10.0.0.0/19"
            [1]: "10.0.32.0/19"
            [2]: "10.0.64.0/19"
            [3]: "10.0.96.0/19"
        ]
        privateSubnetIds          : [
            [0]: "subnet-094a131e3de4d662a"
            [1]: "subnet-02bb109ccfb2af07f"
            [2]: "subnet-063e6f316ac988879"
            [3]: "subnet-0ac8510c3af1194e3"
        ]
        privateSubnetRouteTableIds: [
            [0]: "rtb-0d5631459058a2b60"
            [1]: "rtb-010f6299597ec6e9f"
            [2]: "rtb-0c9e0a3e99d4485aa"
            [3]: "rtb-0200b79a08d3e1298"
        ]
        publicSubnetCidrs         : [
            [0]: "10.0.128.0/20"
            [1]: "10.0.144.0/20"
            [2]: "10.0.160.0/20"
            [3]: "10.0.176.0/20"
        ]
        publicSubnetIds           : [
            [0]: "subnet-037d5b9c4c7b24667"
            [1]: "subnet-0a0aca9810a25638d"
            [2]: "subnet-0b351dbda6f9514ce"
            [3]: "subnet-0e23fd9739ae823cd"
        ]
        publicSubnetRouteTableId  : "rtb-0e42f9cc38b4d49dc"
        s3VpcEndpointId           : "vpce-02310318fa26593ec"
    }

Resources:
    + 40 created
```

## Architecture

This new environment uses the following AWS features:

* *Multi-AZ*. Use up to all of the Availability Zones (AZs) in your chosen region for high availability and disaster
  recovery. AZs are geographically distributed within a region and spaced for best insulation and stability in the
  even of a natural disaster. Maximizing AZ usage helps to insulate your application from a data center outage.

* *Separate subnets*. Public subnets are provisioned for external-facing resources and private subnets for internal
  resourcs. For each AZ, this template will create one public and one private subnet by default.

* *Additional security layers*. Network access control lists (ACLs) and firewalls are used to control inbound
  and outbound traffic at the subnet level. This template provides an option to create a network ACL protected
  subnet in each AZ, providing individual controls that you can use to customize a second layer of defense.

* *Independent routing tables*. Each private subnet gets an independent routing table to control the flow of traffic
  within and outside the VPC. All public subnets share a single routing table as they all share the same Internet
  gateway as the sole route to communicate with the Internet.

* *Highly available NAT gateways*. Using a NAT gateway instead of NAT instances offers advantages in terms of
  deployment, availability, and maintenance.

* *Spare capacity*. As your environment grows over time, this template supports adding additional subnets.

![Architecture Diagram](https://docs.aws.amazon.com/quickstart/latest/vpc/images/quickstart-vpc-design-fullscreen.png)

## Configurable Properties


The VPC component uses sane defaults, however, there are a number of properties you can set by passing them
to your VPC's constructor. This includes:

* `availabilityZones`: an array of AZs to deploy into (defaults to all of the current region's).
* `numberOfAvailabilityZones`: the number of AZs to deploy into (defaults to all of them).
* `createPrivateSubnets`: set to `false` if you want to create only public subnets (defaults to `true`).
* `createProtectedSubnets`: set to `true` to create a network ACL protected subnet in each AZ (defaults to `false`).
* `vpcCidr`: configure VPC's CIDR block (defaults to `10.0.0.0/16`).
* `vpcTenancy`: configure the VPC's tenancy (defaults to `default`).
* `publicSubnetCidrs`: set the CIDR blocks for public subnets (defaults to even spread across AZs).
* `publicSubnetTags`: set the tags for public subnets.
* `privateSubnetCidrs`: set the CIDR blocks for private subnets, if enabled.
* `privateSubnetTags`: set the tags for private subnets, if enabled.
* `protectedSubnetCidrs`: set the CIDR blocks for private NACL subnets, if enabled.
* `protectedSubnetTags`: set the tags for private NACL subnets, if enabled.

## Building From Source

[todo: instructions]

> Note: This example has been adapted from https://aws.amazon.com/quickstart/architecture/vpc/.
