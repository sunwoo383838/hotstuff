package config

config: {
	consensus:      "hotstuff1"
	leaderRotation: "round-robin"
	crypto:         "bls12"
	communication:  "clique"
	byzantineStrategy: {
		"": []
	}
	replicaHosts: ["localhost"]
	clientHosts: ["localhost"]
	replicas: 4
	clients:  1
	sshConfig: "/dev/null"
	duration: 60000000000
	fixedTimeout: 1000000000
	batchSize: 10
	maxConcurrent: 500
	output: "/root/GolandProjects/hotstuff2/output/hotstuff1-aws-01"
	measurementInterval: 100000000
	exe: "/root/GolandProjects/hotstuff2/hotstuff-worker"

	terraform: {
        instanceType: "c7g.16xlarge"
        diskSizeGB: 30
        useSpotInstances: true
        spotTerminationAction: "terminate"
				regions: [
            "eu-west-2",
            "ap-northeast-1",
            "ap-southeast-1",
            "ca-central-1"
        ]
    }
}

