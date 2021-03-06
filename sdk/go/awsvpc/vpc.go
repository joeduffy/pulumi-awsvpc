// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package awsvpc

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type Vpc struct {
	pulumi.ResourceState

	// CIDR block for the VPC.
	CidrBlock pulumi.StringOutput `pulumi:"cidrBlock"`
	// The ID of the underlying AWS VPC.
	Id pulumi.StringOutput `pulumi:"id"`
	// Auto-assigned elastic IP addresses (EIPs) for the NAT gateway(s).
	NatEips pulumi.StringArrayOutput `pulumi:"natEips"`
	// CIDR blocks for private subnets.
	PrivateSubnetCidrs pulumi.StringArrayOutput `pulumi:"privateSubnetCidrs"`
	// IDs for private subnets.
	PrivateSubnetIds pulumi.StringArrayOutput `pulumi:"privateSubnetIds"`
	// Route table IDs for private subnets.
	PrivateSubnetRouteTableIds pulumi.StringArrayOutput `pulumi:"privateSubnetRouteTableIds"`
	// CIDR blocks for protected subnets.
	ProtectedSubnetCidrs pulumi.StringArrayOutput `pulumi:"protectedSubnetCidrs"`
	// IDs for protected subnets.
	ProtectedSubnetIds pulumi.StringArrayOutput `pulumi:"protectedSubnetIds"`
	// CIDR blocks for public subnets.
	PublicSubnetCidrs pulumi.StringArrayOutput `pulumi:"publicSubnetCidrs"`
	// IDs for public subnets.
	PublicSubnetIds pulumi.StringArrayOutput `pulumi:"publicSubnetIds"`
	// Route table ID for public subnets.
	PublicSubnetRouteTableId pulumi.StringOutput `pulumi:"publicSubnetRouteTableId"`
	// If private subnets were created, an S3 VPC Endpoint to simplify S3 access.
	S3VpcEndpointId pulumi.StringPtrOutput `pulumi:"s3VpcEndpointId"`
}

// NewVpc registers a new resource with the given unique name, arguments, and options.
func NewVpc(ctx *pulumi.Context,
	name string, args *VpcArgs, opts ...pulumi.ResourceOption) (*Vpc, error) {
	if args == nil {
		args = &VpcArgs{}
	}

	var resource Vpc
	err := ctx.RegisterRemoteComponentResource("awsvpc:index:Vpc", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

type vpcArgs struct {
	// List of AZs to use for the subnets in the VPC. Note: the logical order is preserved.
	AvailabilityZones []string `pulumi:"availabilityZones"`
	// CIDR block for the VPC.
	CidrBlock *string `pulumi:"cidrBlock"`
	// Set to false to create only public subnets. If false, the CIDR parameters for ALL private subnets will be ignored.
	CreatePrivateSubnets *bool `pulumi:"createPrivateSubnets"`
	// Set to true to create a network ACL protected subnet in each AZ. If false, the CIDR parameters for those subnets will be ignored. If true, it also requires that the `createPrivateSubnets` parameter is also true.
	CreateProtectedSubnets *bool `pulumi:"createProtectedSubnets"`
	// Number of AZs to use in the VPC. If both are specified, this must match your selections in the list of AZs parameter.
	NumberOfAvailabilityZones *int `pulumi:"numberOfAvailabilityZones"`
	// CIDR blocks for private subnets.
	PrivateSubnetCidrs []string `pulumi:"privateSubnetCidrs"`
	// Tags to add to private subnets (an array of maps, one per AZ).
	PrivateSubnetTags []map[string]string `pulumi:"privateSubnetTags"`
	// CIDR blocks for protected subnets.
	ProtectedSubnetCidrs []string `pulumi:"protectedSubnetCidrs"`
	// Tags to add to protected subnets (an array of maps, one per AZ).
	ProtectedSubnetTags []map[string]string `pulumi:"protectedSubnetTags"`
	// CIDR blocks for public subnets.
	PublicSubnetCidrs []string `pulumi:"publicSubnetCidrs"`
	// Tags to add to public subnets (an array of maps, one per AZ).
	PublicSubnetTags []map[string]string `pulumi:"publicSubnetTags"`
	// The allowed tenancy of instances launched into the VPC.
	Tenancy *string `pulumi:"tenancy"`
}

// The set of arguments for constructing a Vpc resource.
type VpcArgs struct {
	// List of AZs to use for the subnets in the VPC. Note: the logical order is preserved.
	AvailabilityZones pulumi.StringArrayInput
	// CIDR block for the VPC.
	CidrBlock pulumi.StringPtrInput
	// Set to false to create only public subnets. If false, the CIDR parameters for ALL private subnets will be ignored.
	CreatePrivateSubnets pulumi.BoolPtrInput
	// Set to true to create a network ACL protected subnet in each AZ. If false, the CIDR parameters for those subnets will be ignored. If true, it also requires that the `createPrivateSubnets` parameter is also true.
	CreateProtectedSubnets pulumi.BoolPtrInput
	// Number of AZs to use in the VPC. If both are specified, this must match your selections in the list of AZs parameter.
	NumberOfAvailabilityZones pulumi.IntPtrInput
	// CIDR blocks for private subnets.
	PrivateSubnetCidrs pulumi.StringArrayInput
	// Tags to add to private subnets (an array of maps, one per AZ).
	PrivateSubnetTags pulumi.StringMapArrayInput
	// CIDR blocks for protected subnets.
	ProtectedSubnetCidrs pulumi.StringArrayInput
	// Tags to add to protected subnets (an array of maps, one per AZ).
	ProtectedSubnetTags pulumi.StringMapArrayInput
	// CIDR blocks for public subnets.
	PublicSubnetCidrs pulumi.StringArrayInput
	// Tags to add to public subnets (an array of maps, one per AZ).
	PublicSubnetTags pulumi.StringMapArrayInput
	// The allowed tenancy of instances launched into the VPC.
	Tenancy pulumi.StringPtrInput
}

func (VpcArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*vpcArgs)(nil)).Elem()
}

type VpcInput interface {
	pulumi.Input

	ToVpcOutput() VpcOutput
	ToVpcOutputWithContext(ctx context.Context) VpcOutput
}

func (*Vpc) ElementType() reflect.Type {
	return reflect.TypeOf((*Vpc)(nil))
}

func (i *Vpc) ToVpcOutput() VpcOutput {
	return i.ToVpcOutputWithContext(context.Background())
}

func (i *Vpc) ToVpcOutputWithContext(ctx context.Context) VpcOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VpcOutput)
}

func (i *Vpc) ToVpcPtrOutput() VpcPtrOutput {
	return i.ToVpcPtrOutputWithContext(context.Background())
}

func (i *Vpc) ToVpcPtrOutputWithContext(ctx context.Context) VpcPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VpcPtrOutput)
}

type VpcPtrInput interface {
	pulumi.Input

	ToVpcPtrOutput() VpcPtrOutput
	ToVpcPtrOutputWithContext(ctx context.Context) VpcPtrOutput
}

type vpcPtrType VpcArgs

func (*vpcPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**Vpc)(nil))
}

func (i *vpcPtrType) ToVpcPtrOutput() VpcPtrOutput {
	return i.ToVpcPtrOutputWithContext(context.Background())
}

func (i *vpcPtrType) ToVpcPtrOutputWithContext(ctx context.Context) VpcPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VpcPtrOutput)
}

// VpcArrayInput is an input type that accepts VpcArray and VpcArrayOutput values.
// You can construct a concrete instance of `VpcArrayInput` via:
//
//          VpcArray{ VpcArgs{...} }
type VpcArrayInput interface {
	pulumi.Input

	ToVpcArrayOutput() VpcArrayOutput
	ToVpcArrayOutputWithContext(context.Context) VpcArrayOutput
}

type VpcArray []VpcInput

func (VpcArray) ElementType() reflect.Type {
	return reflect.TypeOf(([]*Vpc)(nil))
}

func (i VpcArray) ToVpcArrayOutput() VpcArrayOutput {
	return i.ToVpcArrayOutputWithContext(context.Background())
}

func (i VpcArray) ToVpcArrayOutputWithContext(ctx context.Context) VpcArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VpcArrayOutput)
}

// VpcMapInput is an input type that accepts VpcMap and VpcMapOutput values.
// You can construct a concrete instance of `VpcMapInput` via:
//
//          VpcMap{ "key": VpcArgs{...} }
type VpcMapInput interface {
	pulumi.Input

	ToVpcMapOutput() VpcMapOutput
	ToVpcMapOutputWithContext(context.Context) VpcMapOutput
}

type VpcMap map[string]VpcInput

func (VpcMap) ElementType() reflect.Type {
	return reflect.TypeOf((map[string]*Vpc)(nil))
}

func (i VpcMap) ToVpcMapOutput() VpcMapOutput {
	return i.ToVpcMapOutputWithContext(context.Background())
}

func (i VpcMap) ToVpcMapOutputWithContext(ctx context.Context) VpcMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VpcMapOutput)
}

type VpcOutput struct {
	*pulumi.OutputState
}

func (VpcOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*Vpc)(nil))
}

func (o VpcOutput) ToVpcOutput() VpcOutput {
	return o
}

func (o VpcOutput) ToVpcOutputWithContext(ctx context.Context) VpcOutput {
	return o
}

func (o VpcOutput) ToVpcPtrOutput() VpcPtrOutput {
	return o.ToVpcPtrOutputWithContext(context.Background())
}

func (o VpcOutput) ToVpcPtrOutputWithContext(ctx context.Context) VpcPtrOutput {
	return o.ApplyT(func(v Vpc) *Vpc {
		return &v
	}).(VpcPtrOutput)
}

type VpcPtrOutput struct {
	*pulumi.OutputState
}

func (VpcPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Vpc)(nil))
}

func (o VpcPtrOutput) ToVpcPtrOutput() VpcPtrOutput {
	return o
}

func (o VpcPtrOutput) ToVpcPtrOutputWithContext(ctx context.Context) VpcPtrOutput {
	return o
}

type VpcArrayOutput struct{ *pulumi.OutputState }

func (VpcArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]Vpc)(nil))
}

func (o VpcArrayOutput) ToVpcArrayOutput() VpcArrayOutput {
	return o
}

func (o VpcArrayOutput) ToVpcArrayOutputWithContext(ctx context.Context) VpcArrayOutput {
	return o
}

func (o VpcArrayOutput) Index(i pulumi.IntInput) VpcOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) Vpc {
		return vs[0].([]Vpc)[vs[1].(int)]
	}).(VpcOutput)
}

type VpcMapOutput struct{ *pulumi.OutputState }

func (VpcMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]Vpc)(nil))
}

func (o VpcMapOutput) ToVpcMapOutput() VpcMapOutput {
	return o
}

func (o VpcMapOutput) ToVpcMapOutputWithContext(ctx context.Context) VpcMapOutput {
	return o
}

func (o VpcMapOutput) MapIndex(k pulumi.StringInput) VpcOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) Vpc {
		return vs[0].(map[string]Vpc)[vs[1].(string)]
	}).(VpcOutput)
}

func init() {
	pulumi.RegisterOutputType(VpcOutput{})
	pulumi.RegisterOutputType(VpcPtrOutput{})
	pulumi.RegisterOutputType(VpcArrayOutput{})
	pulumi.RegisterOutputType(VpcMapOutput{})
}
