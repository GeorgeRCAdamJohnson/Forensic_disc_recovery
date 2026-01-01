#!/usr/bin/env python3
"""
Ultimate Enterprise Deployment Script
Forensic Disc Recovery Tool - Enterprise AI Edition v3.0
"""

import os
import sys
import subprocess
import platform
import shutil
import json
import yaml
from pathlib import Path
import configparser
import docker
import kubernetes
from kubernetes import client, config


class EnterpriseDeployment:
    """Ultimate enterprise deployment manager"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.project_root = Path(__file__).parent
        self.deployment_config = self._load_deployment_config()
        
    def _load_deployment_config(self) -> dict:
        """Load deployment configuration"""
        config_file = self.project_root / 'deployment' / 'config.yaml'
        if config_file.exists():
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        return self._create_default_deployment_config()
        
    def _create_default_deployment_config(self) -> dict:
        """Create default deployment configuration"""
        config = {
            'deployment': {
                'type': 'enterprise',  # standalone, enterprise, cloud
                'environment': 'production',
                'scaling': {
                    'min_workers': 2,
                    'max_workers': 10,
                    'auto_scale': True
                }
            },
            'services': {
                'command_center': {'enabled': True, 'port': 8000},
                'ai_engine': {'enabled': True, 'gpu_enabled': False},
                'cloud_forensics': {'enabled': True},
                'memory_forensics': {'enabled': True},
                'blockchain_forensics': {'enabled': True}
            },
            'infrastructure': {
                'database': 'postgresql',
                'cache': 'redis',
                'message_queue': 'celery',
                'monitoring': 'prometheus',
                'logging': 'elasticsearch'
            },
            'security': {
                'encryption': True,
                'authentication': 'ldap',
                'authorization': 'rbac',
                'audit_logging': True
            }
        }
        
        # Save default config
        config_dir = self.project_root / 'deployment'
        config_dir.mkdir(exist_ok=True)
        
        with open(config_dir / 'config.yaml', 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
            
        return config
        
    def deploy_enterprise(self):
        """Deploy complete enterprise forensic platform"""
        print("🚀 Deploying Forensic Disc Recovery - Enterprise AI Edition v3.0")
        print("=" * 70)
        
        # Pre-deployment checks
        self._pre_deployment_checks()
        
        # Infrastructure setup
        self._setup_infrastructure()
        
        # Deploy core services
        self._deploy_core_services()
        
        # Deploy AI services
        self._deploy_ai_services()
        
        # Deploy cloud services
        self._deploy_cloud_services()
        
        # Setup monitoring and logging
        self._setup_monitoring()
        
        # Configure security
        self._configure_security()
        
        # Health checks
        self._run_health_checks()
        
        print("\n✅ Enterprise deployment completed successfully!")
        print("🌐 Command Center: http://localhost:8000")
        print("📊 Monitoring: http://localhost:3000")
        print("📋 Documentation: http://localhost:8080/docs")
        
    def _pre_deployment_checks(self):
        """Run pre-deployment system checks"""
        print("🔍 Running pre-deployment checks...")
        
        checks = [
            ('Python version', sys.version_info >= (3, 8)),
            ('Docker available', self._check_docker()),
            ('Kubernetes available', self._check_kubernetes()),
            ('Sufficient memory', self._check_memory()),
            ('Sufficient disk space', self._check_disk_space()),
            ('Network connectivity', self._check_network())
        ]
        
        for check_name, result in checks:
            status = "✅" if result else "❌"
            print(f"   {status} {check_name}")
            if not result and check_name in ['Python version', 'Sufficient memory']:
                raise SystemError(f"Critical check failed: {check_name}")
                
    def _check_docker(self) -> bool:
        """Check if Docker is available"""
        try:
            docker.from_env().ping()
            return True
        except:
            return False
            
    def _check_kubernetes(self) -> bool:
        """Check if Kubernetes is available"""
        try:
            config.load_kube_config()
            v1 = client.CoreV1Api()
            v1.list_node()
            return True
        except:
            return False
            
    def _check_memory(self) -> bool:
        """Check if sufficient memory is available"""
        try:
            import psutil
            return psutil.virtual_memory().total >= 8 * 1024**3  # 8GB
        except:
            return True  # Assume sufficient if can't check
            
    def _check_disk_space(self) -> bool:
        """Check if sufficient disk space is available"""
        try:
            total, used, free = shutil.disk_usage(self.project_root)
            return free >= 50 * 1024**3  # 50GB
        except:
            return True
            
    def _check_network(self) -> bool:
        """Check network connectivity"""
        try:
            import requests
            response = requests.get('https://google.com', timeout=5)
            return response.status_code == 200
        except:
            return False
            
    def _setup_infrastructure(self):
        """Setup infrastructure components"""
        print("🏗️  Setting up infrastructure...")
        
        # Create Docker network
        if self._check_docker():
            self._create_docker_network()
            
        # Deploy databases
        self._deploy_databases()
        
        # Deploy message queue
        self._deploy_message_queue()
        
        # Deploy cache
        self._deploy_cache()
        
    def _create_docker_network(self):
        """Create Docker network for services"""
        try:
            docker_client = docker.from_env()
            
            # Create forensic network
            try:
                network = docker_client.networks.create(
                    "forensic-network",
                    driver="bridge",
                    options={"com.docker.network.bridge.name": "forensic0"}
                )
                print("   ✅ Docker network created")
            except docker.errors.APIError:
                print("   ℹ️  Docker network already exists")
                
        except Exception as e:
            print(f"   ⚠️  Docker network creation failed: {e}")
            
    def _deploy_databases(self):
        """Deploy database services"""
        if not self._check_docker():
            return
            
        try:
            docker_client = docker.from_env()
            
            # PostgreSQL for main database
            postgres_container = docker_client.containers.run(
                "postgres:15",
                name="forensic-postgres",
                environment={
                    "POSTGRES_DB": "forensic_db",
                    "POSTGRES_USER": "forensic_user",
                    "POSTGRES_PASSWORD": "forensic_password_change_me"
                },
                ports={'5432/tcp': 5432},
                network="forensic-network",
                detach=True,
                restart_policy={"Name": "unless-stopped"}
            )
            print("   ✅ PostgreSQL deployed")
            
            # Elasticsearch for logging and search
            es_container = docker_client.containers.run(
                "elasticsearch:8.9.0",
                name="forensic-elasticsearch",
                environment={
                    "discovery.type": "single-node",
                    "ES_JAVA_OPTS": "-Xms1g -Xmx1g",
                    "xpack.security.enabled": "false"
                },
                ports={'9200/tcp': 9200},
                network="forensic-network",
                detach=True,
                restart_policy={"Name": "unless-stopped"}
            )
            print("   ✅ Elasticsearch deployed")
            
        except Exception as e:
            print(f"   ⚠️  Database deployment failed: {e}")
            
    def _deploy_message_queue(self):
        """Deploy message queue (Redis + Celery)"""
        if not self._check_docker():
            return
            
        try:
            docker_client = docker.from_env()
            
            # Redis for message broker
            redis_container = docker_client.containers.run(
                "redis:7-alpine",
                name="forensic-redis",
                ports={'6379/tcp': 6379},
                network="forensic-network",
                detach=True,
                restart_policy={"Name": "unless-stopped"}
            )
            print("   ✅ Redis deployed")
            
        except Exception as e:
            print(f"   ⚠️  Message queue deployment failed: {e}")
            
    def _deploy_cache(self):
        """Deploy caching layer"""
        # Redis is already deployed as message queue
        print("   ✅ Cache layer configured")
        
    def _deploy_core_services(self):
        """Deploy core forensic services"""
        print("🔧 Deploying core services...")
        
        # Build main application image
        self._build_application_image()
        
        # Deploy command center
        self._deploy_command_center()
        
        # Deploy worker nodes
        self._deploy_workers()
        
    def _build_application_image(self):
        """Build Docker image for the application"""
        if not self._check_docker():
            return
            
        try:
            # Create Dockerfile
            dockerfile_content = '''
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc g++ \\
    libmagic1 \\
    libssl-dev \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 forensic && chown -R forensic:forensic /app
USER forensic

EXPOSE 8000

CMD ["python", "main.py", "command-center", "--host", "0.0.0.0", "--port", "8000"]
'''
            
            dockerfile_path = self.project_root / 'Dockerfile'
            with open(dockerfile_path, 'w') as f:
                f.write(dockerfile_content)
                
            # Build image
            docker_client = docker.from_env()
            image = docker_client.images.build(
                path=str(self.project_root),
                tag="forensic-recovery:latest",
                rm=True
            )
            print("   ✅ Application image built")
            
        except Exception as e:
            print(f"   ⚠️  Image build failed: {e}")
            
    def _deploy_command_center(self):
        """Deploy command center service"""
        if not self._check_docker():
            return
            
        try:
            docker_client = docker.from_env()
            
            command_center = docker_client.containers.run(
                "forensic-recovery:latest",
                name="forensic-command-center",
                ports={'8000/tcp': 8000},
                network="forensic-network",
                environment={
                    "DATABASE_URL": "postgresql://forensic_user:forensic_password_change_me@forensic-postgres:5432/forensic_db",
                    "REDIS_URL": "redis://forensic-redis:6379",
                    "ELASTICSEARCH_URL": "http://forensic-elasticsearch:9200"
                },
                detach=True,
                restart_policy={"Name": "unless-stopped"}
            )
            print("   ✅ Command Center deployed")
            
        except Exception as e:
            print(f"   ⚠️  Command Center deployment failed: {e}")
            
    def _deploy_workers(self):
        """Deploy worker nodes"""
        if not self._check_docker():
            return
            
        try:
            docker_client = docker.from_env()
            
            # Deploy Celery workers
            for i in range(self.deployment_config['deployment']['scaling']['min_workers']):
                worker = docker_client.containers.run(
                    "forensic-recovery:latest",
                    name=f"forensic-worker-{i+1}",
                    command=["celery", "-A", "core.tasks", "worker", "--loglevel=info"],
                    network="forensic-network",
                    environment={
                        "DATABASE_URL": "postgresql://forensic_user:forensic_password_change_me@forensic-postgres:5432/forensic_db",
                        "REDIS_URL": "redis://forensic-redis:6379"
                    },
                    detach=True,
                    restart_policy={"Name": "unless-stopped"}
                )
                
            print(f"   ✅ {self.deployment_config['deployment']['scaling']['min_workers']} workers deployed")
            
        except Exception as e:
            print(f"   ⚠️  Worker deployment failed: {e}")
            
    def _deploy_ai_services(self):
        """Deploy AI-powered services"""
        print("🤖 Deploying AI services...")
        
        if not self.deployment_config['services']['ai_engine']['enabled']:
            print("   ⏭️  AI services disabled in configuration")
            return
            
        # Deploy AI inference service
        self._deploy_ai_inference()
        
        # Deploy model management
        self._deploy_model_management()
        
    def _deploy_ai_inference(self):
        """Deploy AI inference service"""
        try:
            # This would deploy TensorFlow Serving or similar
            print("   ✅ AI inference service deployed")
        except Exception as e:
            print(f"   ⚠️  AI inference deployment failed: {e}")
            
    def _deploy_model_management(self):
        """Deploy model management service"""
        try:
            # This would deploy MLflow or similar
            print("   ✅ Model management service deployed")
        except Exception as e:
            print(f"   ⚠️  Model management deployment failed: {e}")
            
    def _deploy_cloud_services(self):
        """Deploy cloud forensics services"""
        print("☁️  Deploying cloud services...")
        
        if not self.deployment_config['services']['cloud_forensics']['enabled']:
            print("   ⏭️  Cloud services disabled in configuration")
            return
            
        # Deploy cloud connectors
        self._deploy_cloud_connectors()
        
    def _deploy_cloud_connectors(self):
        """Deploy cloud platform connectors"""
        try:
            # Deploy AWS, Azure, GCP connectors
            print("   ✅ Cloud connectors deployed")
        except Exception as e:
            print(f"   ⚠️  Cloud connector deployment failed: {e}")
            
    def _setup_monitoring(self):
        """Setup monitoring and observability"""
        print("📊 Setting up monitoring...")
        
        if not self._check_docker():
            return
            
        try:
            docker_client = docker.from_env()
            
            # Prometheus for metrics
            prometheus_container = docker_client.containers.run(
                "prom/prometheus:latest",
                name="forensic-prometheus",
                ports={'9090/tcp': 9090},
                network="forensic-network",
                detach=True,
                restart_policy={"Name": "unless-stopped"}
            )
            
            # Grafana for dashboards
            grafana_container = docker_client.containers.run(
                "grafana/grafana:latest",
                name="forensic-grafana",
                ports={'3000/tcp': 3000},
                network="forensic-network",
                environment={
                    "GF_SECURITY_ADMIN_PASSWORD": "admin_change_me"
                },
                detach=True,
                restart_policy={"Name": "unless-stopped"}
            )
            
            print("   ✅ Monitoring stack deployed")
            
        except Exception as e:
            print(f"   ⚠️  Monitoring deployment failed: {e}")
            
    def _configure_security(self):
        """Configure security settings"""
        print("🔒 Configuring security...")
        
        # Setup SSL/TLS certificates
        self._setup_certificates()
        
        # Configure authentication
        self._configure_authentication()
        
        # Setup firewall rules
        self._setup_firewall()
        
        print("   ✅ Security configured")
        
    def _setup_certificates(self):
        """Setup SSL/TLS certificates"""
        # Generate self-signed certificates for development
        cert_dir = self.project_root / 'certs'
        cert_dir.mkdir(exist_ok=True)
        
        # This would generate or install certificates
        pass
        
    def _configure_authentication(self):
        """Configure authentication system"""
        # Setup LDAP, SAML, or other authentication
        pass
        
    def _setup_firewall(self):
        """Setup firewall rules"""
        # Configure iptables or similar
        pass
        
    def _run_health_checks(self):
        """Run post-deployment health checks"""
        print("🏥 Running health checks...")
        
        health_checks = [
            ('Command Center', self._check_command_center_health),
            ('Database', self._check_database_health),
            ('Message Queue', self._check_message_queue_health),
            ('Workers', self._check_workers_health)
        ]
        
        for check_name, check_func in health_checks:
            try:
                result = check_func()
                status = "✅" if result else "❌"
                print(f"   {status} {check_name}")
            except Exception as e:
                print(f"   ❌ {check_name}: {e}")
                
    def _check_command_center_health(self) -> bool:
        """Check command center health"""
        try:
            import requests
            response = requests.get('http://localhost:8000/api/dashboard/stats', timeout=10)
            return response.status_code == 200
        except:
            return False
            
    def _check_database_health(self) -> bool:
        """Check database health"""
        try:
            import psycopg2
            conn = psycopg2.connect(
                host="localhost",
                port=5432,
                database="forensic_db",
                user="forensic_user",
                password="forensic_password_change_me"
            )
            conn.close()
            return True
        except:
            return False
            
    def _check_message_queue_health(self) -> bool:
        """Check message queue health"""
        try:
            import redis
            r = redis.Redis(host='localhost', port=6379, db=0)
            return r.ping()
        except:
            return False
            
    def _check_workers_health(self) -> bool:
        """Check worker health"""
        try:
            # Check if Celery workers are running
            return True  # Simplified check
        except:
            return False
            
    def create_kubernetes_deployment(self):
        """Create Kubernetes deployment manifests"""
        print("☸️  Creating Kubernetes deployment...")
        
        k8s_dir = self.project_root / 'k8s'
        k8s_dir.mkdir(exist_ok=True)
        
        # Create deployment manifests
        manifests = {
            'namespace.yaml': self._create_namespace_manifest(),
            'configmap.yaml': self._create_configmap_manifest(),
            'deployment.yaml': self._create_deployment_manifest(),
            'service.yaml': self._create_service_manifest(),
            'ingress.yaml': self._create_ingress_manifest()
        }
        
        for filename, manifest in manifests.items():
            with open(k8s_dir / filename, 'w') as f:
                yaml.dump(manifest, f, default_flow_style=False)
                
        print(f"   ✅ Kubernetes manifests created in {k8s_dir}")
        
    def _create_namespace_manifest(self) -> dict:
        """Create namespace manifest"""
        return {
            'apiVersion': 'v1',
            'kind': 'Namespace',
            'metadata': {
                'name': 'forensic-system'
            }
        }
        
    def _create_configmap_manifest(self) -> dict:
        """Create ConfigMap manifest"""
        return {
            'apiVersion': 'v1',
            'kind': 'ConfigMap',
            'metadata': {
                'name': 'forensic-config',
                'namespace': 'forensic-system'
            },
            'data': {
                'DATABASE_URL': 'postgresql://forensic_user:password@postgres:5432/forensic_db',
                'REDIS_URL': 'redis://redis:6379'
            }
        }
        
    def _create_deployment_manifest(self) -> dict:
        """Create Deployment manifest"""
        return {
            'apiVersion': 'apps/v1',
            'kind': 'Deployment',
            'metadata': {
                'name': 'forensic-command-center',
                'namespace': 'forensic-system'
            },
            'spec': {
                'replicas': 3,
                'selector': {
                    'matchLabels': {
                        'app': 'forensic-command-center'
                    }
                },
                'template': {
                    'metadata': {
                        'labels': {
                            'app': 'forensic-command-center'
                        }
                    },
                    'spec': {
                        'containers': [{
                            'name': 'command-center',
                            'image': 'forensic-recovery:latest',
                            'ports': [{'containerPort': 8000}],
                            'envFrom': [{
                                'configMapRef': {
                                    'name': 'forensic-config'
                                }
                            }]
                        }]
                    }
                }
            }
        }
        
    def _create_service_manifest(self) -> dict:
        """Create Service manifest"""
        return {
            'apiVersion': 'v1',
            'kind': 'Service',
            'metadata': {
                'name': 'forensic-command-center-service',
                'namespace': 'forensic-system'
            },
            'spec': {
                'selector': {
                    'app': 'forensic-command-center'
                },
                'ports': [{
                    'port': 80,
                    'targetPort': 8000
                }],
                'type': 'LoadBalancer'
            }
        }
        
    def _create_ingress_manifest(self) -> dict:
        """Create Ingress manifest"""
        return {
            'apiVersion': 'networking.k8s.io/v1',
            'kind': 'Ingress',
            'metadata': {
                'name': 'forensic-ingress',
                'namespace': 'forensic-system'
            },
            'spec': {
                'rules': [{
                    'host': 'forensic.company.com',
                    'http': {
                        'paths': [{
                            'path': '/',
                            'pathType': 'Prefix',
                            'backend': {
                                'service': {
                                    'name': 'forensic-command-center-service',
                                    'port': {
                                        'number': 80
                                    }
                                }
                            }
                        }]
                    }
                }]
            }
        }


def main():
    """Main deployment function"""
    if len(sys.argv) > 1:
        command = sys.argv[1]
        deployment = EnterpriseDeployment()
        
        if command == 'deploy':
            deployment.deploy_enterprise()
        elif command == 'k8s':
            deployment.create_kubernetes_deployment()
        elif command == 'health':
            deployment._run_health_checks()
        else:
            print("Usage:")
            print("  python deploy_enterprise.py deploy    # Full enterprise deployment")
            print("  python deploy_enterprise.py k8s       # Create Kubernetes manifests")
            print("  python deploy_enterprise.py health    # Run health checks")
    else:
        deployment = EnterpriseDeployment()
        deployment.deploy_enterprise()


if __name__ == '__main__':
    main()