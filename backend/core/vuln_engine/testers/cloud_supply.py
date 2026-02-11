"""
NeuroSploit v3 - Cloud & Supply Chain Vulnerability Testers

Testers for S3 misconfiguration, cloud metadata, subdomain takeover,
vulnerable dependencies, container escape, and serverless misconfiguration.
"""
import re
from typing import Tuple, Dict, Optional
from backend.core.vuln_engine.testers.base_tester import BaseTester


class S3BucketMisconfigTester(BaseTester):
    """Tester for S3 Bucket Misconfiguration vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "s3_bucket_misconfig"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for S3 bucket listing or misconfiguration"""
        # Bucket listing XML response
        if re.search(r"<ListBucketResult\s", response_body):
            return True, 0.95, "S3 bucket listing enabled - bucket contents exposed"

        # Bucket listing with objects
        if "<Contents>" in response_body and "<Key>" in response_body:
            keys = re.findall(r"<Key>([^<]+)</Key>", response_body)
            if keys:
                return True, 0.95, f"S3 bucket listing: {len(keys)} objects exposed (e.g., {keys[0][:50]})"

        # NoSuchBucket - potential subdomain takeover
        if "NoSuchBucket" in response_body:
            bucket_match = re.search(r"<BucketName>([^<]+)</BucketName>", response_body)
            bucket_name = bucket_match.group(1) if bucket_match else "unknown"
            return True, 0.8, f"S3 bucket '{bucket_name}' does not exist - potential takeover"

        # AccessDenied with bucket info
        if "AccessDenied" in response_body and "s3.amazonaws.com" in response_body:
            return True, 0.5, "S3 bucket exists but access denied - bucket enumerated"

        # Public write/upload success
        if response_status in [200, 204] and context.get("is_upload_test"):
            headers_lower = {k.lower(): v for k, v in response_headers.items()}
            if "x-amz-request-id" in headers_lower:
                return True, 0.9, "S3 bucket allows public write access"

        # Bucket policy exposed
        if '"Statement"' in response_body and '"Effect"' in response_body:
            if '"s3:' in response_body:
                return True, 0.85, "S3 bucket policy exposed"

        return False, 0.0, None


class CloudMetadataExposureTester(BaseTester):
    """Tester for Cloud Metadata Exposure vulnerabilities (SSRF to metadata)"""

    def __init__(self):
        super().__init__()
        self.name = "cloud_metadata_exposure"
        self.metadata_indicators = {
            # AWS
            "aws": [
                (r"ami-[0-9a-f]{8,17}", "AWS AMI ID"),
                (r"i-[0-9a-f]{8,17}", "AWS Instance ID"),
                (r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:", "AWS ARN"),
                (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
                (r"169\.254\.169\.254", "AWS metadata endpoint"),
                (r"\"(?:AccessKeyId|SecretAccessKey|Token)\"", "AWS IAM credentials"),
                (r"ec2\.internal", "AWS internal hostname"),
                (r"\"accountId\"\s*:\s*\"\d{12}\"", "AWS Account ID"),
            ],
            # GCP
            "gcp": [
                (r"projects/\d+/", "GCP Project reference"),
                (r"metadata\.google\.internal", "GCP metadata endpoint"),
                (r"\"access_token\"\s*:\s*\"ya29\.", "GCP OAuth token"),
                (r"compute\.googleapis\.com", "GCP Compute API"),
                (r"serviceAccounts/[^/]+/token", "GCP service account token"),
            ],
            # Azure
            "azure": [
                (r"metadata\.azure\.com", "Azure metadata endpoint"),
                (r"(?:subscriptionId|resourceGroupName)\"\s*:\s*\"", "Azure resource info"),
                (r"\.blob\.core\.windows\.net", "Azure Blob Storage"),
                (r"\.vault\.azure\.net", "Azure Key Vault"),
                (r"\"access_token\"\s*:\s*\"eyJ", "Azure JWT token"),
            ],
        }

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for cloud metadata in response"""
        findings = []

        for provider, patterns in self.metadata_indicators.items():
            for pattern, description in patterns:
                if re.search(pattern, response_body):
                    findings.append(f"{provider.upper()}: {description}")

        if findings:
            # IAM credentials or tokens are critical
            critical = any(k in f for f in findings for k in ["credentials", "Access Key", "token", "Token"])
            confidence = 0.95 if critical else 0.8
            return True, confidence, f"Cloud metadata exposure: {', '.join(findings[:3])}"

        # Check for metadata endpoint access (SSRF to cloud metadata)
        metadata_urls = ["169.254.169.254", "metadata.google.internal",
                         "metadata.azure.com", "100.100.100.200"]
        for url in metadata_urls:
            if url in payload and response_status == 200 and len(response_body) > 50:
                return True, 0.85, f"Cloud metadata accessible via SSRF ({url})"

        return False, 0.0, None


class SubdomainTakeoverTester(BaseTester):
    """Tester for Subdomain Takeover vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "subdomain_takeover"
        self.takeover_fingerprints = [
            # AWS S3
            (r"NoSuchBucket", "S3 bucket - NoSuchBucket"),
            (r"The specified bucket does not exist", "S3 bucket does not exist"),
            # GitHub Pages
            (r"There isn't a GitHub Pages site here", "GitHub Pages - unclaimed"),
            (r"For root URLs.*GitHub Pages", "GitHub Pages not configured"),
            # Heroku
            (r"No such app", "Heroku - app not found"),
            (r"herokucdn\.com/error-pages/no-such-app", "Heroku - no such app"),
            # Shopify
            (r"Sorry, this shop is currently unavailable", "Shopify - shop unavailable"),
            # Tumblr
            (r"There's nothing here\.", "Tumblr - unclaimed"),
            (r"Whatever you were looking for doesn't currently exist", "Tumblr not found"),
            # WordPress.com
            (r"Do you want to register.*wordpress\.com", "WordPress.com - unclaimed"),
            # Azure
            (r"404 Web Site not found", "Azure - web app not found"),
            # Fastly
            (r"Fastly error: unknown domain", "Fastly - unknown domain"),
            # Pantheon
            (r"404 error unknown site", "Pantheon - unknown site"),
            # Zendesk
            (r"Help Center Closed", "Zendesk - closed"),
            # Unbounce
            (r"The requested URL was not found on this server.*unbounce", "Unbounce - not found"),
            # Surge.sh
            (r"project not found", "Surge.sh - not found"),
            # Fly.io
            (r"404.*fly\.io", "Fly.io - not found"),
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for cloud provider error pages indicating takeover opportunity"""
        for pattern, description in self.takeover_fingerprints:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.9, f"Subdomain takeover: {description}"

        # CNAME pointing to unclaimed resource
        if context.get("cname_target"):
            cname = context["cname_target"]
            unclaimed_domains = [
                ".s3.amazonaws.com", ".herokuapp.com", ".github.io",
                ".azurewebsites.net", ".cloudfront.net", ".fastly.net",
                ".ghost.io", ".myshopify.com", ".surge.sh",
            ]
            for domain in unclaimed_domains:
                if cname.endswith(domain) and response_status in [404, 0]:
                    return True, 0.85, f"Subdomain takeover: CNAME to {cname} returns {response_status}"

        # NXDOMAIN with CNAME
        if context.get("dns_nxdomain") and context.get("has_cname"):
            return True, 0.8, "Subdomain takeover: CNAME exists but target domain is NXDOMAIN"

        return False, 0.0, None


class VulnerableDependencyTester(BaseTester):
    """Tester for Vulnerable Dependency detection"""

    def __init__(self):
        super().__init__()
        self.name = "vulnerable_dependency"
        self.vulnerable_libs = [
            # JavaScript
            (r"jquery[/.-](?:1\.\d+|2\.\d+|3\.[0-4]\.\d+)", "jQuery < 3.5.0 (XSS)"),
            (r"angular[/.-]1\.[0-5]\.\d+", "AngularJS < 1.6 (sandbox escape)"),
            (r"lodash[/.-](?:[0-3]\.\d+|4\.(?:1[0-6]|[0-9])\.\d+)", "Lodash < 4.17.21 (prototype pollution)"),
            (r"bootstrap[/.-](?:[1-3]\.\d+|4\.[0-3]\.\d+)", "Bootstrap < 4.3.1 (XSS)"),
            (r"moment[/.-](?:[01]\.\d+|2\.(?:[0-9]|1[0-8])\.\d+)", "Moment.js < 2.19.3 (ReDoS)"),
            (r"handlebars[/.-](?:[0-3]\.\d+|4\.[0-6]\.\d+)", "Handlebars < 4.7.7 (prototype pollution)"),
            # Python
            (r"Django[/=](?:1\.\d+|2\.[01]\.\d+|3\.0\.\d+)", "Django < 3.1 (multiple CVEs)"),
            (r"Flask[/=](?:0\.\d+|1\.[01]\.\d+)", "Flask < 2.0 (known issues)"),
            (r"requests[/=]2\.(?:[0-9]|1\d|2[0-4])\.\d+", "Requests < 2.25 (CVE-2023-32681)"),
            # Java
            (r"log4j[/-]2\.(?:[0-9]|1[0-4])\.\d+", "Log4j < 2.15 (Log4Shell CVE-2021-44228)"),
            (r"spring-core[/-](?:[1-4]\.\d+|5\.[0-2]\.\d+)", "Spring < 5.3 (Spring4Shell)"),
            (r"jackson-databind[/-]2\.(?:[0-8]|9\.[0-9])\.\d*", "Jackson < 2.9.10 (deserialization)"),
            # PHP
            (r"laravel/framework[/:]\s*v?(?:[1-7]\.\d+|8\.[0-7]\d)", "Laravel < 8.80 (known issues)"),
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for known vulnerable library version strings"""
        findings = []

        # Check response body (JS files, package.json, error pages)
        for pattern, description in self.vulnerable_libs:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                findings.append(f"{match.group(0)} - {description}")

        # Check headers for version info
        headers_str = "\n".join(f"{k}: {v}" for k, v in response_headers.items())
        for pattern, description in self.vulnerable_libs:
            match = re.search(pattern, headers_str, re.IGNORECASE)
            if match and description not in str(findings):
                findings.append(f"{match.group(0)} - {description}")

        if findings:
            # Log4Shell and Spring4Shell are critical
            critical = any(k in f for f in findings for k in ["Log4Shell", "Spring4Shell", "deserialization"])
            confidence = 0.9 if critical else 0.75
            return True, confidence, f"Vulnerable dependency: {'; '.join(findings[:3])}"

        return False, 0.0, None


class ContainerEscapeTester(BaseTester):
    """Tester for Container Escape / Container Misconfiguration vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "container_escape"
        self.container_indicators = [
            # Docker
            (r"\.dockerenv", "Docker environment file accessible"),
            (r"docker\.sock", "Docker socket exposed"),
            (r"/var/run/docker\.sock", "Docker socket path"),
            # Cgroup
            (r"docker[/-][0-9a-f]{12,64}", "Docker container cgroup"),
            (r"/proc/self/cgroup.*docker", "Docker cgroup detected"),
            (r"/proc/self/cgroup.*kubepods", "Kubernetes pod cgroup"),
            # Kubernetes
            (r"KUBERNETES_SERVICE_HOST", "Kubernetes service host env"),
            (r"KUBERNETES_PORT", "Kubernetes port env"),
            (r"/var/run/secrets/kubernetes\.io", "Kubernetes secrets path"),
            (r"serviceaccount/token", "Kubernetes service account token"),
            (r"kube-system", "Kubernetes system namespace"),
            # Container runtime
            (r"containerd", "containerd runtime"),
            (r"runc", "runc runtime"),
            # Process namespace
            (r"process\s+1\b.*(?:init|systemd|tini|dumb-init)", "Container init process"),
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for Docker/container indicators in response"""
        findings = []

        for pattern, description in self.container_indicators:
            if re.search(pattern, response_body, re.IGNORECASE):
                findings.append(description)

        if findings:
            # Docker socket or K8s secrets are critical
            critical = any(k in f for f in findings for k in ["socket", "secrets", "token"])
            confidence = 0.9 if critical else 0.7
            return True, confidence, f"Container exposure: {', '.join(findings[:3])}"

        # Privileged container detection
        if context.get("is_capability_check"):
            # Check for extra capabilities
            cap_patterns = [
                r"cap_sys_admin", r"cap_sys_ptrace", r"cap_net_admin",
                r"cap_dac_override", r"cap_sys_rawio",
            ]
            for pattern in cap_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True, 0.8, f"Privileged container: {pattern} capability detected"

        # Mount namespace check
        if re.search(r"/dev/(?:sda|xvda|nvme)\d*\s", response_body):
            return True, 0.6, "Host block devices visible from container"

        return False, 0.0, None


class ServerlessMisconfigTester(BaseTester):
    """Tester for Serverless Misconfiguration vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "serverless_misconfig"
        self.env_patterns = [
            # AWS Lambda
            (r"AWS_LAMBDA_FUNCTION_NAME\s*[=:]\s*(\S+)", "Lambda function name"),
            (r"AWS_SECRET_ACCESS_KEY\s*[=:]\s*(\S+)", "Lambda AWS secret key"),
            (r"AWS_SESSION_TOKEN\s*[=:]\s*(\S+)", "Lambda session token"),
            (r"AWS_LAMBDA_LOG_GROUP_NAME", "Lambda log group"),
            (r"_HANDLER\s*[=:]\s*(\S+)", "Lambda handler path"),
            (r"LAMBDA_TASK_ROOT\s*[=:]\s*(\S+)", "Lambda task root"),
            (r"AWS_EXECUTION_ENV\s*[=:]\s*(\S+)", "Lambda execution environment"),
            # Google Cloud Functions
            (r"FUNCTION_NAME\s*[=:]\s*(\S+)", "Cloud Function name"),
            (r"GCLOUD_PROJECT\s*[=:]\s*(\S+)", "GCP project ID"),
            (r"GOOGLE_CLOUD_PROJECT\s*[=:]\s*(\S+)", "GCP project"),
            (r"GCP_PROJECT\s*[=:]\s*(\S+)", "GCP project"),
            (r"FUNCTION_REGION\s*[=:]\s*(\S+)", "Cloud Function region"),
            # Azure Functions
            (r"FUNCTIONS_WORKER_RUNTIME\s*[=:]\s*(\S+)", "Azure Function runtime"),
            (r"AzureWebJobsStorage\s*[=:]\s*(\S+)", "Azure storage connection string"),
            (r"WEBSITE_SITE_NAME\s*[=:]\s*(\S+)", "Azure site name"),
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for serverless environment variable exposure"""
        findings = []

        for pattern, description in self.env_patterns:
            match = re.search(pattern, response_body)
            if match:
                value = match.group(1) if match.lastindex else ""
                # Redact sensitive values
                if "key" in description.lower() or "token" in description.lower() or "secret" in description.lower():
                    display = f"{description} (REDACTED)"
                else:
                    display = f"{description}: {value[:30]}"
                findings.append(display)

        if findings:
            # Credentials are critical
            critical = any(k in f for f in findings for k in ["secret", "token", "REDACTED"])
            confidence = 0.95 if critical else 0.75
            return True, confidence, f"Serverless misconfiguration: {', '.join(findings[:3])}"

        # Function source code exposure
        if context.get("is_source_request"):
            source_indicators = [
                r"exports\.handler\s*=", r"def lambda_handler\(",
                r"def main\(req:", r"module\.exports",
                r"def hello_http\(request\):",
            ]
            for pattern in source_indicators:
                if re.search(pattern, response_body):
                    return True, 0.8, "Serverless misconfiguration: function source code exposed"

        # Invocation error details
        error_patterns = [
            r"\"errorType\"\s*:\s*\"(\w+)\"",
            r"\"stackTrace\"\s*:\s*\[",
            r"Runtime\.HandlerNotFound",
            r"\"errorMessage\"\s*:\s*\".*(?:import|require|module)",
        ]
        for pattern in error_patterns:
            match = re.search(pattern, response_body)
            if match:
                return True, 0.7, f"Serverless misconfiguration: detailed error exposed ({match.group(0)[:60]})"

        return False, 0.0, None
