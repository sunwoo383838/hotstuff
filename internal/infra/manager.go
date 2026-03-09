package infra

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/relab/hotstuff/internal/config"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var regionAMIMapARM64 = map[string]string{
	// Asia Pacific
	"ap-northeast-1": "ami-0c0f9a31a751af6b2", // Tokyo,  Ubuntu 22.04 LTS ARM64, 2025-11-22
	"ap-northeast-2": "ami-066c6675b3b454c0c", // Seoul,  Ubuntu 22.04 LTS ARM64, 2025-11-22
	"ap-southeast-1": "ami-0f2eeea15aa543011", // Singapore, Ubuntu 22.04 LTS ARM64, 2025-11-22
	"ap-southeast-2": "ami-001d15f74cae057d8", // Sydney, Ubuntu 22.04 LTS ARM64, 2025-11-22

	// US
	"us-east-1": "ami-0a105b59f5c9471cb", // N. Virginia, Ubuntu 22.04 LTS ARM64, 2025-11-22
	"us-east-2": "ami-09e413920c38b7571", // Ohio,        Ubuntu 22.04 LTS ARM64, 2025-11-22
	"us-west-2": "ami-0b9a0e4bd28ad4afe", // Oregon,      Ubuntu 22.04 LTS ARM64, 2025-11-22

	// Europe
	"eu-west-2":    "ami-0df8754b32e6455a2", // London,     Ubuntu 22.04 LTS ARM64, 2025-11-22
	"eu-central-1": "ami-0e0b1be40503e4745", // Frankfurt,  Ubuntu 22.04 LTS ARM64, 2025-11-22
	"eu-south-2":   "ami-0e6cc710bcf21e0df", // Spain,      Ubuntu 22.04 LTS ARM64, 2025-11-22

	// South America
	"sa-east-1": "ami-0dd9b850a44237141", // São Paulo,   Ubuntu 22.04 LTS ARM64, 2025-11-22

	// Canada
	"ca-central-1": "ami-01d6d170418d5c803", // Canada (Central), Ubuntu 22.04 LTS ARM64, 2025-11-22
}

var regionAZs = map[string][]string{
	// Asia Pacific
	"ap-northeast-2": {"ap-northeast-2a", "ap-northeast-2b", "ap-northeast-2c", "ap-northeast-2d"}, // Seoul (4 AZs)
	"ap-southeast-1": {"ap-southeast-1a", "ap-southeast-1b", "ap-southeast-1c"},                    // Singapore (3 AZs)
	"ap-southeast-2": {"ap-southeast-2a", "ap-southeast-2b", "ap-southeast-2c"},                    // Sydney (3 AZs)
	"ap-northeast-1": {"ap-northeast-1a", "ap-northeast-1b", "ap-northeast-1c", "ap-northeast-1d"}, // Tokyo (4 AZs)

	// US
	"us-east-1": {"us-east-1a", "us-east-1b", "us-east-1c", "us-east-1d", "us-east-1e", "us-east-1f"}, // N. Virginia (6 AZs)
	"us-east-2": {"us-east-2a", "us-east-2b", "us-east-2c"},                                           // Ohio (3 AZs)
	"us-west-2": {"us-west-2a", "us-west-2b", "us-west-2c", "us-west-2d"},                             // Oregon (4 AZs)

	// Europe
	"eu-west-2":    {"eu-west-2a", "eu-west-2b", "eu-west-2c"},          // London (3 AZs)
	"eu-central-1": {"eu-central-1a", "eu-central-1b", "eu-central-1c"}, // Frankfurt (3 AZs)
	"eu-south-2":   {"eu-south-2a", "eu-south-2b", "eu-south-2c"},       // Spain (3 AZs)

	// South America
	"sa-east-1": {"sa-east-1a", "sa-east-1b", "sa-east-1c"}, // São Paulo (3 AZs)

	// Canada
	"ca-central-1": {"ca-central-1a", "ca-central-1b", "ca-central-1c"}, // Canada (Central) (3 AZs)
}

type TerraformManager struct {
	tf      *tfexec.Terraform
	cfg     *config.TerraformConfig
	workDir string

	varKVs []string

	applyOpts   []tfexec.ApplyOption
	destroyOpts []tfexec.DestroyOption

	sshPublicKey      string
	sshPrivateKeyPath string
}

type InstanceDetail struct {
	Index      int
	Name       string
	Zone       string
	PublicIP   string
	InternalIP string
}

// TerraformOutput은 Terraform apply 후 출력 값들입니다.
type TerraformOutput struct {
	InstanceDetails     []InstanceDetail
	InstancePublicIPs   []string
	InstanceInternalIPs []string
	InstanceZones       []string
	ZoneDistribution    map[string]int
	TotalInstances      int
	SSHPrivateKeyPath   string
}

// NewManager는 새로운 Manager 인스턴스를 생성하고 초기화합니다.
func NewTerraformManager(cfg *config.TerraformConfig) (*TerraformManager, error) {
	// 1. Terraform 실행 파일 확보 (없으면 자동 설치)
	execPath, err := ensureTerraform()
	if err != nil {
		return nil, fmt.Errorf("terraform 준비 실패: %w", err)
	}
	log.Printf("Terraform 실행 파일: %s", execPath)
	workDir := "./terraform" // ← main.tf 등이 있는 디렉터리로 지정
	if _, err := os.Stat(filepath.Join(workDir, "main.tf")); err != nil {
		return nil, fmt.Errorf("terraform module not found at %s: %w", workDir, err)
	}

	tf, err := tfexec.NewTerraform(workDir, execPath)
	if err != nil {
		return nil, fmt.Errorf("terraform executor 생성 실패: %w", err)
	}

	tf.SetStdout(os.Stdout)
	tf.SetStderr(os.Stderr)

	if err := tf.Init(context.Background(), tfexec.Upgrade(true)); err != nil {
		return nil, fmt.Errorf("terraform init 실패: %w", err)
	}

	pubKey, privPath, err := generateExperimentSSHKey(workDir)
	if err != nil {
		return nil, fmt.Errorf("SSH 키 로딩 실패: %w", err)
	}

	return &TerraformManager{
		tf:                tf,
		cfg:               cfg,
		workDir:           workDir,
		sshPublicKey:      pubKey,
		sshPrivateKeyPath: privPath,
	}, nil
}

func generateExperimentSSHKey(workDir string) (pubKey string, privPath string, err error) {
	keyName := "hotstuff-experiment"
	privPath = filepath.Join(workDir, "experiment_ssh_key")
	pubPath := privPath + ".pub"

	os.Remove(privPath)
	os.Remove(pubPath)

	// ssh-keygen으로 새 키 생성 (ed25519, passphrase 없음)
	cmd := exec.Command(
		"ssh-keygen",
		"-t", "ed25519",
		"-N", "",
		"-C", keyName,
		"-f", privPath,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Printf("실험용 SSH 키 생성 중: %s", privPath)
	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("ssh-keygen 실행 실패: %w", err)
	}

	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return "", "", fmt.Errorf("생성된 SSH 공개키 읽기 실패: %w", err)
	}

	return strings.TrimSpace(string(pubBytes)), privPath, nil
}

// ensureTerraform은 시스템에 Terraform이 설치되어 있는지 확인하고,
// 없으면 자동으로 설치합니다.
func ensureTerraform() (string, error) {
	// 1. 시스템에 이미 설치된 terraform 확인
	if path, err := exec.LookPath("terraform"); err == nil {
		return path, nil
	}

	installer := &releases.ExactVersion{
		Product: product.Terraform,
		Version: version.Must(version.NewVersion("1.9.0")),
	}

	return installer.Install(context.Background())
}
func (m *TerraformManager) Provision(totalReplicas int) (*TerraformOutput, error) {
	ctx := context.Background()
	log.Printf("========== 멀티 리전 프로비저닝 시작 (%d Replicas) ==========", totalReplicas)

	regions := m.cfg.Regions
	if len(regions) == 0 {
		return nil, fmt.Errorf("설정된 리전이 없습니다 (Regions array is empty)")
	}

	// 1. 리전별 할당량 계산
	regionCounts := distributeUnits(totalReplicas, len(regions))

	finalOutput := &TerraformOutput{
		InstanceDetails:     []InstanceDetail{},
		InstancePublicIPs:   []string{},
		InstanceInternalIPs: []string{},
		InstanceZones:       []string{},
		ZoneDistribution:    make(map[string]int),
	}

	finalOutput.SSHPrivateKeyPath = m.sshPrivateKeyPath

	// 2. 각 리전별 배포 루프
	for i, region := range regions {
		replicaCount := regionCounts[i]
		if replicaCount == 0 {
			continue
		}

		log.Printf(">>> 리전 배포 시작: %s (할당된 Replicas: %d)", region, replicaCount)

		// 2-1. Workspace 전환 (상태 격리)
		wsName := fmt.Sprintf("ws_%s", strings.ReplaceAll(region, "-", "_"))
		if err := m.selectOrCreateWorkspace(ctx, wsName); err != nil {
			return nil, err
		}

		// 2-2. AMI 결정 (인스턴스 타입에 따라 맵 선택 필요, 여기선 ARM64 가정)
		// 만약 config.InstanceType이 x86이면 regionAMIMap 사용
		// 편의상 ARM64 맵을 사용한다고 가정 (c7g 타입)
		amiID, ok := regionAMIMapARM64[region]
		if !ok {
			return nil, fmt.Errorf("해당 리전(%s)에 대한 AMI 매핑을 찾을 수 없습니다", region)
		}

		// 2-3. 리전 내 AZ 분배 및 zone_allocations JSON 생성
		zonesJSON, err := m.createZoneAllocationsJSON(region, replicaCount)
		if err != nil {
			return nil, err
		}

		// 2-4. 변수 설정
		vars := []tfexec.ApplyOption{
			tfexec.Var(fmt.Sprintf("region=%s", region)),
			tfexec.Var(fmt.Sprintf("zone_allocations=%s", zonesJSON)),
			tfexec.Var(fmt.Sprintf("ami=%s", amiID)),
			tfexec.Var(fmt.Sprintf("instance_type=%s", m.cfg.InstanceType)),
			tfexec.Var(fmt.Sprintf("disk_size_gb=%d", m.cfg.DiskSizeGB)),
			tfexec.Var(fmt.Sprintf("ssh_public_key=%s", m.sshPublicKey)),
			tfexec.Var(fmt.Sprintf("ssh_key_name=%s", "hotstuff-bench-key")),
		}
		if m.cfg.UseSpotInstances {
			vars = append(vars, tfexec.Var("use_spot_instances=true"))
		}
		if m.cfg.SpotTerminationAction != "" {
			vars = append(vars, tfexec.Var(fmt.Sprintf("spot_termination_action=%s", m.cfg.SpotTerminationAction)))
		}

		// 2-5. Apply 실행
		log.Printf("[%s] Terraform apply 실행 중...", region)
		if err := m.tf.Apply(ctx, vars...); err != nil {
			return nil, fmt.Errorf("[%s] Apply 실패: %w", region, err)
		}

		// 2-6. Output 수집 및 병합
		partialOutput, err := m.readOutputs(ctx)
		if err != nil {
			return nil, fmt.Errorf("[%s] Output 읽기 실패: %w", region, err)
		}

		finalOutput.TotalInstances += partialOutput.TotalInstances
		finalOutput.InstancePublicIPs = append(finalOutput.InstancePublicIPs, partialOutput.InstancePublicIPs...)
		finalOutput.InstanceInternalIPs = append(finalOutput.InstanceInternalIPs, partialOutput.InstanceInternalIPs...)
		finalOutput.InstanceZones = append(finalOutput.InstanceZones, partialOutput.InstanceZones...)

		// InstanceDetails 인덱스 조정 (전역 유니크하게)
		currentIndexOffset := len(finalOutput.InstanceDetails)
		for _, detail := range partialOutput.InstanceDetails {
			detail.Index += currentIndexOffset // 인덱스를 이어서 붙임
			finalOutput.InstanceDetails = append(finalOutput.InstanceDetails, detail)
		}

		// Zone 분포 합산
		for z, c := range partialOutput.ZoneDistribution {
			finalOutput.ZoneDistribution[z] = c
		}
	}

	log.Printf("✓ 모든 리전 배포 완료. 총 인스턴스: %d", finalOutput.TotalInstances)

	// 3. SSH 접속 대기
	log.Printf("인스턴스 부팅 및 SSH 대기 중...")
	if err := m.waitForInstances(finalOutput.InstancePublicIPs); err != nil {
		log.Printf("경고: 일부 인스턴스 접속 실패: %v", err)
	} else {
		log.Printf("✓ 모든 인스턴스 준비 완료")
	}

	m.logProvisioningSummary(finalOutput)
	return finalOutput, nil
}

func (m *TerraformManager) Teardown() error {
	log.Printf("========== 인프라 정리 시작 ==========")
	ctx := context.Background()
	regions := m.cfg.Regions

	for _, region := range regions {
		wsName := fmt.Sprintf("ws_%s", strings.ReplaceAll(region, "-", "_"))

		if err := m.tf.WorkspaceSelect(ctx, wsName); err != nil {
			log.Printf("[%s] 워크스페이스 선택 실패(이미 삭제됨?): %v", region, err)
			continue
		}

		log.Printf("[%s] 리소스 삭제 중 (Destroy)...", region)

		emptyAlloc := "[]"

		destroyVars := []tfexec.DestroyOption{
			tfexec.Var(fmt.Sprintf("region=%s", region)),
			tfexec.Var(fmt.Sprintf("zone_allocations=%s", emptyAlloc)),
			tfexec.Var("ami=ami-dummy"),
			tfexec.Var(fmt.Sprintf("ssh_public_key=%s", m.sshPublicKey)),
		}

		if err := m.tf.Destroy(ctx, destroyVars...); err != nil {
			log.Printf("[%s] Destroy 실패: %v", region, err)
		} else {
			log.Printf("[%s] 삭제 완료", region)
		}
	}

	// 기본 워크스페이스로 복귀
	_ = m.tf.WorkspaceSelect(ctx, "default")

	log.Printf("========== 인프라 정리 완료 ==========")
	return nil
}

// 헬퍼: 워크스페이스 선택 또는 생성
func (m *TerraformManager) selectOrCreateWorkspace(ctx context.Context, name string) error {
	wsList, _, err := m.tf.WorkspaceList(ctx) // ← 여기 수정: 두 번째 리턴값 무시
	if err != nil {
		return fmt.Errorf("workspace list 조회 실패: %w", err)
	}

	exists := false
	for _, ws := range wsList {
		if ws == name {
			exists = true
			break
		}
	}

	if exists {
		return m.tf.WorkspaceSelect(ctx, name)
	}
	return m.tf.WorkspaceNew(ctx, name)
}

func (m *TerraformManager) createZoneAllocationsJSON(region string, count int) (string, error) {
	azList, ok := regionAZs[region]
	if !ok || len(azList) == 0 {
		return "", fmt.Errorf("리전 %s 에 대해 정의된 AZ 리스트가 없습니다", region)
	}

	azCounts := make(map[string]int)
	for i := 0; i < count; i++ {
		az := azList[i%len(azList)] // AZ 갯수만큼 라운드로빈
		azCounts[az]++
	}

	type Alloc struct {
		Zone  string `json:"zone"`
		Count int    `json:"count"`
	}
	var allocs []Alloc
	for z, c := range azCounts {
		allocs = append(allocs, Alloc{Zone: z, Count: c})
	}

	bytes, err := json.Marshal(allocs)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// 헬퍼: 정수 균등 분배 (예: 10개, 3그룹 -> 4, 3, 3)
func distributeUnits(total, buckets int) []int {
	if buckets == 0 {
		return nil
	}
	base := total / buckets
	remainder := total % buckets
	res := make([]int, buckets)
	for i := 0; i < buckets; i++ {
		res[i] = base
		if i < remainder {
			res[i]++
		}
	}
	return res
}

func (m *TerraformManager) readOutputs(ctx context.Context) (*TerraformOutput, error) {
	rawOutput, err := m.tf.Output(ctx)
	if err != nil {
		return nil, err
	}
	output := &TerraformOutput{}

	if v, ok := rawOutput["instance_details"]; ok {
		json.Unmarshal(v.Value, &output.InstanceDetails)
	}
	if v, ok := rawOutput["instance_public_ips"]; ok {
		json.Unmarshal(v.Value, &output.InstancePublicIPs)
	}
	if v, ok := rawOutput["instance_internal_ips"]; ok {
		json.Unmarshal(v.Value, &output.InstanceInternalIPs)
	}
	if v, ok := rawOutput["instance_zones"]; ok {
		json.Unmarshal(v.Value, &output.InstanceZones)
	}
	if v, ok := rawOutput["zone_distribution"]; ok {
		json.Unmarshal(v.Value, &output.ZoneDistribution)
	}
	if v, ok := rawOutput["total_instances"]; ok {
		var f float64
		json.Unmarshal(v.Value, &f)
		output.TotalInstances = int(f)
	}
	return output, nil
}

func (m *TerraformManager) waitForInstances(ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	const maxRetries = 40
	const retryInterval = 5 * time.Second
	const connectTimeout = 5

	keyPath := m.sshPrivateKeyPath

	failedIPs := []string{}
	for i, ip := range ips {
		log.Printf("[%d/%d] Connecting to %s...", i+1, len(ips), ip)
		connected := false
		for r := 0; r < maxRetries; r++ {
			cmd := exec.Command("ssh",
				"-i", keyPath,
				"-o", "StrictHostKeyChecking=no",
				"-o", "UserKnownHostsFile=/dev/null",
				"-o", fmt.Sprintf("ConnectTimeout=%d", connectTimeout),
				"-o", "LogLevel=ERROR",
				fmt.Sprintf("ubuntu@%s", ip),
				"echo ready")

			if err := cmd.Run(); err == nil {
				connected = true
				break
			}
			time.Sleep(retryInterval)
		}
		if !connected {
			failedIPs = append(failedIPs, ip)
			log.Printf("Failed to connect to %s", ip)
		}
	}
	if len(failedIPs) > 0 {
		return fmt.Errorf("connection failed for: %v", failedIPs)
	}
	return nil
}

func (m *TerraformManager) saveSSHKey(privateKey string) error {
	// 이미 파일로 존재하므로 로깅만 수행하거나 생략
	return nil
}

func (m *TerraformManager) logProvisioningSummary(output *TerraformOutput) {
	log.Printf("=== 최종 배포 결과 ===")
	log.Printf("총 인스턴스: %d", output.TotalInstances)
	log.Printf("AZ 분포: %v", output.ZoneDistribution)
	if len(output.InstancePublicIPs) > 0 {
		log.Printf("SSH 접속 예시: ssh -i %s ubuntu@%s", m.sshPrivateKeyPath, output.InstancePublicIPs[0])
	}
}

func (m *TerraformManager) GetSSHKeyPath() string {
	return m.sshPrivateKeyPath
}

func (m *TerraformManager) ValidateConfiguration() error {
	if m.cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if len(m.cfg.Regions) == 0 {
		return fmt.Errorf("regions list is empty")
	}
	return nil
}
