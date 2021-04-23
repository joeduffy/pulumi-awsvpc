// Copyright 2016-2021, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package provider

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi-aws/sdk/v3/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v3/go/aws/ec2"
	awsconfig "github.com/pulumi/pulumi-aws/sdk/v4/go/aws/config"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

var VPCToken = "awsvpc:index:Vpc"

// constructVPC converts the raw ConstructInputs coming from a Pulumi engine RPC into the component's
// strongly typed arguments struct, creates the component, and then returns its URN and state (outputs).
func constructVPC(ctx *pulumi.Context, name string, inputs *pulumi.ConstructInputs,
	options pulumi.ResourceOption) (pulumi.ConstructResult, error) {
	// Copy the raw inputs to VPCArgs. `inputs.SetArgs` uses the types and `pulumi:` tags
	// on the struct's fields to convert the raw values to the appropriate Input types.
	args := &VPCArgs{}
	if err := inputs.SetArgs(args); err != nil {
		return pulumi.ConstructResult{}, errors.Wrap(err, "setting args")
	}

	// If no availability zones were provider, load the default ones for the current region.
	if args.AvailabilityZones == nil {
		currentZones, err := aws.GetAvailabilityZones(ctx, nil)
		if err != nil {
			return pulumi.ConstructResult{}, errors.Wrap(err, "loading default availability zones")
		}
		names := currentZones.Names
		args.AvailabilityZones = &names
	}

	// Create the component resource.
	staticPage, outs, err := NewVPC(ctx, name, args, options)
	if err != nil {
		return pulumi.ConstructResult{}, errors.Wrap(err, "creating component")
	}

	// Return the component resource's URN and outputs as its state.
	return pulumi.ConstructResult{
		URN:   staticPage.URN(),
		State: outs,
	}, nil
}

// VPCArgs contains the set of arguments for creating a VPC component resource.
// TODO: there are a lot of settings we want to consider, e.g. see our AWSX VPC component.
// TODO: many of these should accept pulumi.InputX types. But not all of them! For instance, a lot of
//     resource creation is dependent on number of AZs. We faced similar issues with the AWSX VPC component,
//     so we should probably do a debrief on what worked well, versus did not work well, over there.
type VPCArgs struct {
	// List of AZs to use for the subnets in the VPC. Note: the logical order is preserved.
	AvailabilityZones *[]string `pulumi:"availabilityZones"`
	// Number of AZs to use in the VPC. If both are specified, this must match your selections in the list of AZs parameter.
	NumberOfAvailabilityZones *int `pulumi:"numberOfAvailabilityZones"`
	// Set to false to create only public subnets. If false, the CIDR parameters for ALL private subnets will be ignored.
	CreatePrivateSubnets *bool `pulumi:"createPrivateSubnets"`
	// Set to true to create a network ACL protected subnet in each AZ. If false, the CIDR parameters for those
	// subnets will be ignored. If true, it also requires that the `createPrivateSubnets` parameter is also true.
	CreateProtectedSubnets *bool `pulumi:"createProtectedSubnets"`
	// CIDR block for the VPC.
	CIDRBlock *string `pulumi:"cidrBlock"`
	// The allowed tenancy of instances launched into the VPC.
	Tenancy *string `pulumi:"tenancy"`
	// CIDR blocks for public subnets.
	PublicSubnetCIDRs *[]string `pulumi:"publicSubnetCidrs"`
	// Tag to add to public subnets (an array of maps, one per AZ).
	PublicSubnetTags *[]map[string]string `pulumi:"publicSubnetTags"`
	// CIDR blocks for private subnets.
	PrivateSubnetCIDRs *[]string `pulumi:"privateSubnetCidrs"`
	// Tag to add to private subnets (an array of maps, one per AZ).
	PrivateSubnetTags *[]map[string]string `pulumi:"privateSubnetTags"`
	// CIDR blocks for private NACL'd subnets.
	ProtectedSubnetCIDRs *[]string `pulumi:"protectedSubnetCidrs"`
	// Tag to add to private NACL'd subnets (an array of maps, one per AZ).
	ProtectedSubnetTags *[]map[string]string `pulumi:"protectedSubnetTags"`
}

// Define some standard defaults for CIDR blocks if they aren't specified explicitly.
var (
	defaultVPCCIDR                 = "10.0.0.0/16"
	defaultVPCTenancy              = "default"
	defaultVPCPublicSubnetCIDRs    = []string{"10.0.128.0/20", "10.0.144.0/20", "10.0.160.0/20", "10.0.176.0/20"}
	defaultVPCPrivateSubnetCIDRs   = []string{"10.0.0.0/19", "10.0.32.0/19", "10.0.64.0/19", "10.0.96.0/19"}
	defaultVPCProtectedSubnetCIDRs = []string{"10.0.192.0/21", "10.0.200.0/21", "10.0.208.0/21", "10.0.216.0/21"}
)

// GetAvailabilityZones returns the list of AZs this VPC should use, based on configuration parameters. If
// "availabilityZones" is set, those exact zones are returned; else if "numberOfAzs" is set, the first AZs up
// to that count are returned; otherwise, all AZs in the current region are returned.
func (args *VPCArgs) GetAvailabilityZones() []string {
	if args.AvailabilityZones == nil {
		return []string{}
	}
	azs := *args.AvailabilityZones

	// Default to two AZs if unspecified.
	if args.NumberOfAvailabilityZones == nil {
		return azs[:2]
	}
	return azs[:*args.NumberOfAvailabilityZones]
}

// GetPublicSubnetCIDRs returns a list of CIDR blocks to use for public subnets, one per AZ.
func (args *VPCArgs) GetPublicSubnetCIDRs() []string {
	if args.PublicSubnetCIDRs != nil {
		return *args.PublicSubnetCIDRs
	}
	return defaultVPCPublicSubnetCIDRs[:len(args.GetAvailabilityZones())]
}

// GetPublicSubnetTags returns a list of tag maps to be used for public subnets, one per AZ.
func (args *VPCArgs) GetPublicSubnetTags() []map[string]string {
	if args.PublicSubnetTags != nil {
		return *args.PublicSubnetTags
	}
	var tags []map[string]string
	for range args.GetAvailabilityZones() {
		tags = append(tags, map[string]string{"Network": "Public"})
	}
	return tags
}

func (args *VPCArgs) ShouldCreatePrivateSubnets() bool {
	// Default to creating private subnets, but this can be overridden.
	if args.CreatePrivateSubnets != nil && *args.CreatePrivateSubnets == false {
		return false
	}
	return true
}

// GetPrivateSubnetCIDR returns a list of CIDR blocks to use for private subnets, one per AZ.
func (args *VPCArgs) GetPrivateSubnetCIDRs() []string {
	// Default to creating private subnets, but this can be overridden.
	if !args.ShouldCreatePrivateSubnets() {
		return nil
	}
	if args.PrivateSubnetCIDRs != nil {
		return *args.PrivateSubnetCIDRs
	}
	return defaultVPCPrivateSubnetCIDRs[:len(args.GetAvailabilityZones())]
}

// GetPrivateSubnetTags returns a list of tag maps to be used for private subnets, one per AZ.
func (args *VPCArgs) GetPrivateSubnetTags() []map[string]string {
	if !args.ShouldCreatePrivateSubnets() {
		return nil
	} else if args.PrivateSubnetTags != nil {
		return *args.PrivateSubnetTags
	}
	var tags []map[string]string
	for range args.GetAvailabilityZones() {
		tags = append(tags, map[string]string{"Network": "Private"})
	}
	return tags
}

func (args *VPCArgs) ShouldCreateProtectedSubnets() bool {
	// Default to *not* creating protected subnets, unless explicitly requested.
	if args.CreateProtectedSubnets != nil && *args.CreateProtectedSubnets == true {
		return true
	}
	return false
}

// GetProtectedSubnetCIDRs returns a list of CIDR blocks to use for NACL'd private subnets, one per AZ.
func (args *VPCArgs) GetProtectedSubnetCIDRs() []string {
	if !args.ShouldCreateProtectedSubnets() {
		return nil
	}
	if args.ProtectedSubnetCIDRs != nil {
		return *args.ProtectedSubnetCIDRs
	}
	return defaultVPCProtectedSubnetCIDRs[:len(args.GetAvailabilityZones())]
}

// GetProtectedSubnetTags returns a list of tag maps to be used for NACL'd private subnets, one per AZ.
func (args *VPCArgs) GetProtectedSubnetTags() []map[string]string {
	if !args.ShouldCreateProtectedSubnets() {
		return nil
	} else if args.ProtectedSubnetTags != nil {
		return *args.ProtectedSubnetTags
	}
	var tags []map[string]string
	for range args.GetAvailabilityZones() {
		tags = append(tags, map[string]string{"Network": "Private"})
	}
	return tags
}

// VPC represents an Amazon Virtual Private Cloud (VPC) component resource. This component provisions
// public, private and optionally, protected, subnets, with appropriate route tables, spread across a
// configurable number of availability zones. It is meant to represent automatic well architected best
// practices, with enough customizability to be usable in real world scenarios.
type VPC struct {
	pulumi.ResourceState

	ID                         pulumi.IDOutput          `pulumi:"id"`
	CIDRBlock                  pulumi.StringOutput      `pulumi:"cidrBlock"`
	NATEIPS                    pulumi.StringArrayOutput `pulumi:"natEips"`
	PublicSubnetIDs            pulumi.IDArrayOutput     `pulumi:"publicSubnetIds"`
	PublicSubnetCIDRs          pulumi.StringArrayOutput `pulumi:"publicSubnetCidrs"`
	PublicSubnetRouteTableID   pulumi.IDOutput          `pulumi:"publicSubnetRouteTableId"`
	PrivateSubnetIDs           pulumi.IDArrayOutput     `pulumi:"privateSubnetIds"`
	PrivateSubnetCIDRs         pulumi.StringArrayOutput `pulumi:"privateSubnetCidrs"`
	ProtectedSubnetIDs         pulumi.IDArrayOutput     `pulumi:"protectedSubnetIds"`
	ProtectedSubnetCIDRs       pulumi.StringArrayOutput `pulumi:"protectedSubnetCidrs"`
	PrivateSubnetRouteTableIDs pulumi.IDArrayOutput     `pulumi:"privateSubnetRouteTableIds"`
	S3VPCEndpointID            pulumi.IDOutput          `pulumi:"s3VpcEndpointId"`
}

// NewVPC creates a new VPC component resource.
func NewVPC(ctx *pulumi.Context,
	name string, args *VPCArgs, opts ...pulumi.ResourceOption) (*VPC, pulumi.Map, error) {
	if args == nil {
		args = &VPCArgs{}
	}

	res := &VPC{}
	err := ctx.RegisterComponentResource(VPCToken, name, res, opts...)
	if err != nil {
		return nil, nil, err
	}

	// Define the VPC.
	var cidr string
	if args.CIDRBlock == nil {
		cidr = defaultVPCCIDR
	} else {
		cidr = *args.CIDRBlock
	}
	var tenancy string
	if args.Tenancy == nil {
		tenancy = defaultVPCTenancy
	} else {
		tenancy = *args.Tenancy
	}
	vpc, err := ec2.NewVpc(ctx, "VPC", &ec2.VpcArgs{
		CidrBlock:          pulumi.String(cidr),
		InstanceTenancy:    pulumi.String(tenancy),
		EnableDnsSupport:   pulumi.Bool(true),
		EnableDnsHostnames: pulumi.Bool(true),
		Tags:               pulumi.StringMap{"Name": pulumi.String(ctx.Project() + "-" + ctx.Stack())},
	}, pulumi.Parent(res))
	if err != nil {
		return nil, nil, err
	}

	// Read the AWS region, since some logic below depends on it.
	region := awsconfig.GetRegion(ctx)

	// Associate DHCP options with our VPC.
	var domainName string
	if region == "us-east-1" {
		domainName = "ec2.internal"
	} else {
		domainName = region + ".compute.internal"
	}
	dhcpOptions, err := ec2.NewVpcDhcpOptions(ctx, "DHCPOptions", &ec2.VpcDhcpOptionsArgs{
		DomainName:        pulumi.String(domainName),
		DomainNameServers: pulumi.StringArray{pulumi.String("AmazonProvidedDNS")},
	}, pulumi.Parent(res))
	if err != nil {
		return nil, nil, err
	}
	_, err = ec2.NewVpcDhcpOptionsAssociation(ctx, "VPCDHCPOptionsAssociation", &ec2.VpcDhcpOptionsAssociationArgs{
		VpcId:         vpc.ID(),
		DhcpOptionsId: dhcpOptions.ID(),
	}, pulumi.Parent(res))
	if err != nil {
		return nil, nil, err
	}

	// Create an Internet Gateway for our public subnet to connect to the Internet.
	internetGateway, err := ec2.NewInternetGateway(ctx, "InternetGateway", &ec2.InternetGatewayArgs{
		VpcId: vpc.ID(),
		Tags:  pulumi.StringMap{"Name": pulumi.String(ctx.Project() + "-" + ctx.Stack())},
	}, pulumi.Parent(res))
	if err != nil {
		return nil, nil, err
	}

	// Creat a Route Table for public subnets to use the Internet Gateway for 0.0.0.0/0 traffic.
	publicSubnetRouteTable, err := ec2.NewRouteTable(ctx, "PublicSubnetRouteTable", &ec2.RouteTableArgs{
		VpcId: vpc.ID(),
		Tags: pulumi.StringMap{
			"Name":    pulumi.String("Public Subnets"),
			"Network": pulumi.String("Public"),
		},
	}, pulumi.Parent(res))
	if err != nil {
		return nil, nil, err
	}
	_, err = ec2.NewRoute(ctx, "PublicSubnetRoute", &ec2.RouteArgs{
		RouteTableId:         publicSubnetRouteTable.ID(),
		DestinationCidrBlock: pulumi.String("0.0.0.0/0"),
		GatewayId:            internetGateway.ID(),
	}, pulumi.Parent(res))
	if err != nil {
		return nil, nil, err
	}

	// For each AZ, create the NAT Gateways and public and private subnets. Keep track of various properties
	// so that they can be exported as top-level stack exports later on.
	var natEips []pulumi.StringOutput
	var publicSubnetIds []pulumi.IDOutput
	var privateSubnetIds []pulumi.IDOutput
	var protectedSubnetIds []pulumi.IDOutput
	var privateSubnetRouteTableIds []pulumi.IDOutput
	publicSubnetCidrs := args.GetPublicSubnetCIDRs()
	publicSubnetTags := args.GetPublicSubnetTags()
	privateSubnetCidrs := args.GetPrivateSubnetCIDRs()
	privateSubnetTags := args.GetPrivateSubnetTags()
	protectedSubnetCidrs := args.GetProtectedSubnetCIDRs()
	protectedSubnetTags := args.GetProtectedSubnetTags()

	for i, az := range args.GetAvailabilityZones() {
		// Each AZ gets a public subnet.
		publicSubnetI := fmt.Sprintf("PublicSubnet%d", i)
		publicSubnetTags[i]["Name"] = fmt.Sprintf("Public subnet %d", i)
		publicSubnet, err := ec2.NewSubnet(ctx, publicSubnetI, &ec2.SubnetArgs{
			VpcId:               vpc.ID(),
			AvailabilityZone:    pulumi.String(az),
			CidrBlock:           pulumi.String(publicSubnetCidrs[i]),
			MapPublicIpOnLaunch: pulumi.Bool(true),
			Tags:                goMapToPulumiMap(publicSubnetTags[i]),
		}, pulumi.Parent(res))
		if err != nil {
			return nil, nil, err
		}
		publicSubnetIds = append(publicSubnetIds, publicSubnet.ID())

		_, err = ec2.NewRouteTableAssociation(ctx, publicSubnetI+"RouteTableAssociation", &ec2.RouteTableAssociationArgs{
			SubnetId:     publicSubnet.ID(),
			RouteTableId: publicSubnetRouteTable.ID(),
		}, pulumi.Parent(res))
		if err != nil {
			return nil, nil, err
		}

		// If desired, create a NAT Gateway and private subnet for each AZ.
		if args.ShouldCreatePrivateSubnets() {
			natEip, err := ec2.NewEip(ctx, fmt.Sprintf("NAT%dEIP", i), &ec2.EipArgs{
				Vpc: pulumi.Bool(true),
			}, pulumi.Parent(res), pulumi.DependsOn([]pulumi.Resource{internetGateway}))
			if err != nil {
				return nil, nil, err
			}
			natGateway, err := ec2.NewNatGateway(ctx, fmt.Sprintf("NATGateway%d", i), &ec2.NatGatewayArgs{
				SubnetId:     publicSubnet.ID(),
				AllocationId: natEip.ID(),
			}, pulumi.Parent(res))
			if err != nil {
				return nil, nil, err
			}
			natEips = append(natEips, natEip.PublicIp)

			privateSubnetI := fmt.Sprintf("PrivateSubnet%dA", i)
			privateSubnetTags[i]["Name"] = fmt.Sprintf("Private subnet %dA", i)
			privateSubnet, err := ec2.NewSubnet(ctx, privateSubnetI, &ec2.SubnetArgs{
				VpcId:            vpc.ID(),
				AvailabilityZone: pulumi.String(az),
				CidrBlock:        pulumi.String(privateSubnetCidrs[i]),
				Tags:             goMapToPulumiMap(privateSubnetTags[i]),
			}, pulumi.Parent(res))
			if err != nil {
				return nil, nil, err
			}
			privateSubnetIds = append(privateSubnetIds, privateSubnet.ID())

			privateSubnetRouteTable, err := ec2.NewRouteTable(ctx, privateSubnetI+"RouteTable", &ec2.RouteTableArgs{
				VpcId: vpc.ID(),
				Tags: pulumi.StringMap{
					"Name":    pulumi.String(fmt.Sprintf("Private subnet %dA", i)),
					"Network": pulumi.String("Private"),
				},
			}, pulumi.Parent(res))
			if err != nil {
				return nil, nil, err
			}
			_, err = ec2.NewRoute(ctx, privateSubnetI+"Route", &ec2.RouteArgs{
				RouteTableId:         privateSubnetRouteTable.ID(),
				DestinationCidrBlock: pulumi.String("0.0.0.0/0"),
				NatGatewayId:         natGateway.ID(),
			}, pulumi.Parent(res))
			if err != nil {
				return nil, nil, err
			}
			_, err = ec2.NewRouteTableAssociation(ctx, privateSubnetI+"RouteTableAssociation", &ec2.RouteTableAssociationArgs{
				SubnetId:     privateSubnet.ID(),
				RouteTableId: privateSubnetRouteTable.ID(),
			}, pulumi.Parent(res))
			if err != nil {
				return nil, nil, err
			}

			// Remember the route table ID for the VPC endpoint later.
			privateSubnetRouteTableIds = append(privateSubnetRouteTableIds, privateSubnetRouteTable.ID())

			// If desired, create additional private subnets with dedicated network ACLs for extra protection.
			if args.ShouldCreateProtectedSubnets() {
				protectedSubnetI := fmt.Sprintf("PrivateSubnet%dB", i)
				protectedSubnetTags[i]["Name"] = fmt.Sprintf("Private subnet %dB", i)
				protectedSubnet, err := ec2.NewSubnet(ctx, protectedSubnetI, &ec2.SubnetArgs{
					VpcId:            vpc.ID(),
					AvailabilityZone: pulumi.String(az),
					CidrBlock:        pulumi.String(protectedSubnetCidrs[i]),
					Tags:             goMapToPulumiMap(protectedSubnetTags[i]),
				}, pulumi.Parent(res))
				if err != nil {
					return nil, nil, err
				}
				protectedSubnetIds = append(protectedSubnetIds, protectedSubnet.ID())

				protectedSubnetRouteTable, err := ec2.NewRouteTable(ctx, protectedSubnetI+"RouteTable", &ec2.RouteTableArgs{
					VpcId: vpc.ID(),
					Tags: pulumi.StringMap{
						"Name":    pulumi.String(fmt.Sprintf("Private subnet %dB", i)),
						"Network": pulumi.String("Private"),
					},
				}, pulumi.Parent(res))
				if err != nil {
					return nil, nil, err
				}
				_, err = ec2.NewRoute(ctx, protectedSubnetI+"Route", &ec2.RouteArgs{
					RouteTableId:         protectedSubnetRouteTable.ID(),
					DestinationCidrBlock: pulumi.String("0.0.0.0/0"),
					NatGatewayId:         natGateway.ID(),
				}, pulumi.Parent(res))
				if err != nil {
					return nil, nil, err
				}
				_, err = ec2.NewRouteTableAssociation(ctx, protectedSubnetI+"RouteTableAssociation", &ec2.RouteTableAssociationArgs{
					SubnetId:     protectedSubnet.ID(),
					RouteTableId: protectedSubnetRouteTable.ID(),
				}, pulumi.Parent(res))
				if err != nil {
					return nil, nil, err
				}
				protectedSubnetNetworkAcl, err := ec2.NewNetworkAcl(ctx, protectedSubnetI+"NetworkAcl", &ec2.NetworkAclArgs{
					VpcId:     vpc.ID(),
					SubnetIds: pulumi.StringArray{protectedSubnet.ID()},
					Tags: pulumi.StringMap{
						"Name":    pulumi.String(fmt.Sprintf("NACL protected subnet %d", i)),
						"Network": pulumi.String("NACL Protected"),
					},
				}, pulumi.Parent(res))
				if err != nil {
					return nil, nil, err
				}
				_, err = ec2.NewNetworkAclRule(ctx, protectedSubnetI+"NetworkAclEntryInbound", &ec2.NetworkAclRuleArgs{
					NetworkAclId: protectedSubnetNetworkAcl.ID(),
					CidrBlock:    pulumi.String("0.0.0.0/0"),
					Egress:       pulumi.Bool(false),
					Protocol:     pulumi.String("-1"),
					RuleAction:   pulumi.String("allow"),
					RuleNumber:   pulumi.Int(100),
				}, pulumi.Parent(res))
				if err != nil {
					return nil, nil, err
				}
				_, err = ec2.NewNetworkAclRule(ctx, protectedSubnetI+"NetworkAclEntryOutbound", &ec2.NetworkAclRuleArgs{
					NetworkAclId: protectedSubnetNetworkAcl.ID(),
					CidrBlock:    pulumi.String("0.0.0.0/0"),
					Egress:       pulumi.Bool(true),
					Protocol:     pulumi.String("-1"),
					RuleAction:   pulumi.String("allow"),
					RuleNumber:   pulumi.Int(100),
				}, pulumi.Parent(res))
				if err != nil {
					return nil, nil, err
				}

				// Remember the route table ID for the VPC endpoint later.
				privateSubnetRouteTableIds = append(privateSubnetRouteTableIds, protectedSubnetRouteTable.ID())
			}
		}
	}

	// If we created private subnets, allocate an S3 VPC Endpoint to simplify access to S3.
	var s3VpcEndpointId pulumi.IDOutput
	if args.ShouldCreatePrivateSubnets() {
		s3VpcPolicy := `{
	"Version": "2012-10-17",
	"Statement": [{
		"Action": "*",
		"Effect": "Allow",
		"Resource": "*",
		"Principal": "*"
	}]
}
`
		s3VpcEndpoint, err := ec2.NewVpcEndpoint(ctx, "S3VPCEndpoint", &ec2.VpcEndpointArgs{
			VpcId:         vpc.ID(),
			Policy:        pulumi.String(s3VpcPolicy),
			RouteTableIds: idOutputArrayToStringOutputArray(privateSubnetRouteTableIds),
			ServiceName:   pulumi.String(fmt.Sprintf("com.amazonaws.%s.s3", region)),
		}, pulumi.Parent(res))
		if err != nil {
			return nil, nil, err
		}
		s3VpcEndpointId = s3VpcEndpoint.ID()
	}

	// Export all of the resulting properties that upstream stacks may want to consume.
	res.ID = vpc.ID()
	res.CIDRBlock = vpc.CidrBlock
	res.NATEIPS = stringOutputArrayToStringArrayOutput(natEips)
	res.PublicSubnetIDs = idOutputArrayToIDArrayOutput(publicSubnetIds)
	res.PublicSubnetCIDRs = goStringArrayToPulumiStringArray(publicSubnetCidrs).ToStringArrayOutput()
	res.PublicSubnetRouteTableID = publicSubnetRouteTable.ID()
	res.PrivateSubnetIDs = idOutputArrayToIDArrayOutput(privateSubnetIds)
	res.PrivateSubnetCIDRs = goStringArrayToPulumiStringArray(privateSubnetCidrs).ToStringArrayOutput()
	res.ProtectedSubnetIDs = idOutputArrayToIDArrayOutput(protectedSubnetIds)
	res.ProtectedSubnetCIDRs = goStringArrayToPulumiStringArray(protectedSubnetCidrs).ToStringArrayOutput()
	res.PrivateSubnetRouteTableIDs = idOutputArrayToIDArrayOutput(privateSubnetRouteTableIds)
	res.S3VPCEndpointID = s3VpcEndpointId

	outs := pulumi.Map{
		"id":                         res.ID,
		"cidrBlock":                  res.CIDRBlock,
		"natEips":                    res.NATEIPS,
		"publicSubnetIds":            res.PublicSubnetIDs,
		"publicSubnetCidrs":          res.PublicSubnetCIDRs,
		"publicSubnetRouteTableId":   res.PublicSubnetRouteTableID,
		"privateSubnetIds":           res.PrivateSubnetIDs,
		"privateSubnetCidrs":         res.PrivateSubnetCIDRs,
		"protectedSubnetIds":         res.ProtectedSubnetIDs,
		"protectedSubnetCidrs":       res.ProtectedSubnetCIDRs,
		"privateSubnetRouteTableIds": res.PrivateSubnetRouteTableIDs,
		"s3VpcEndpointId":            res.S3VPCEndpointID,
	}
	if err := ctx.RegisterResourceOutputs(vpc, outs); err != nil {
		return nil, nil, err
	}

	return res, outs, nil
}
