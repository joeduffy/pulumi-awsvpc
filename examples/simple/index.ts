import * as awsvpc from "@pulumi/awsvpc";

const vpc = new awsvpc.Vpc("my-vpc");

export const vpcId = vpc.id;
