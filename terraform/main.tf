# QuantumGuard Infrastructure as Code
# Terraform configuration for cloud-agnostic deployment

terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }
}

# Local variables
locals {
  app_name     = "quantumguard"
  environment  = "development"
  namespace    = "quantumguard-system"
  image_tag    = "latest"
}

# Docker provider configuration
provider "docker" {
  host = "unix:///var/run/docker.sock"
}

# Kubernetes provider configuration
provider "kubernetes" {
  config_path = "~/.kube/config"
}

# Create Docker network
resource "docker_network" "quantumguard_network" {
  name   = "${local.app_name}-network"
  driver = "bridge"

  ipam_config {
    subnet = "172.20.0.0/16"
  }
}

# Create Docker volume for data persistence
resource "docker_volume" "quantumguard_data" {
  name = "${local.app_name}-data"
}

# Build and run OWASP Juice Shop container
resource "docker_image" "juice_shop" {
  name = "quantumguard-app:${local.image_tag}"

  build {
    context    = "../"
    dockerfile = "docker/Dockerfile"
    tag        = ["quantumguard-app:${local.image_tag}"]
  }

  triggers = {
    dir_sha1 = sha1(join("", [for f in fileset("../", "**") : filesha1(f)]))
  }
}

resource "docker_container" "juice_shop" {
  name  = "${local.app_name}-app"
  image = docker_image.juice_shop.image_id

  networks_advanced {
    name = docker_network.quantumguard_network.name
  }

  ports {
    internal = 3000
    external = 3000
  }

  volumes {
    volume_name    = docker_volume.quantumguard_data.name
    container_path = "/app/data"
  }

  env = [
    "NODE_ENV=production",
    "PORT=3000"
  ]

  healthcheck {
    test     = ["CMD", "curl", "-f", "http://localhost:3000/api/status"]
    interval = "30s"
    timeout  = "10s"
    retries  = 3
  }

  restart = "unless-stopped"
}

# Build and run Dashboard container
resource "docker_image" "dashboard" {
  name = "quantumguard-dashboard:${local.image_tag}"

  build {
    context    = "../dashboard"
    dockerfile = "Dockerfile"
    tag        = ["quantumguard-dashboard:${local.image_tag}"]
  }

  triggers = {
    dir_sha1 = sha1(join("", [for f in fileset("../dashboard", "**") : filesha1(f)]))
  }
}

resource "docker_container" "dashboard" {
  name  = "${local.app_name}-dashboard"
  image = docker_image.dashboard.image_id

  networks_advanced {
    name = docker_network.quantumguard_network.name
  }

  ports {
    internal = 5000
    external = 5000
  }

  volumes {
    host_path      = abspath("../data")
    container_path = "/app/data"
  }

  volumes {
    host_path      = abspath("../reports")
    container_path = "/app/reports"
  }

  env = [
    "FLASK_ENV=production",
    "REPORTS_DIR=/app/reports",
    "DATA_DIR=/app/data"
  ]

  depends_on = [docker_container.juice_shop]

  restart = "unless-stopped"
}

# Kubernetes namespace
resource "kubernetes_namespace" "quantumguard" {
  metadata {
    name = local.namespace
    labels = {
      app         = local.app_name
      environment = local.environment
    }
  }
}

# Kubernetes deployment for Juice Shop
resource "kubernetes_deployment" "juice_shop" {
  metadata {
    name      = "${local.app_name}-app"
    namespace = kubernetes_namespace.quantumguard.metadata[0].name
    labels = {
      app = local.app_name
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = local.app_name
      }
    }

    template {
      metadata {
        labels = {
          app = local.app_name
        }
      }

      spec {
        container {
          name  = "juice-shop"
          image = "quantumguard-app:${local.image_tag}"

          port {
            container_port = 3000
          }

          env {
            name  = "NODE_ENV"
            value = "production"
          }

          env {
            name  = "PORT"
            value = "3000"
          }

          resources {
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
            requests = {
              cpu    = "250m"
              memory = "256Mi"
            }
          }

          liveness_probe {
            http_get {
              path = "/api/status"
              port = 3000
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }

          readiness_probe {
            http_get {
              path = "/api/status"
              port = 3000
            }
            initial_delay_seconds = 5
            period_seconds        = 5
          }

          security_context {
            run_as_non_root = true
            run_as_user     = 1000
            run_as_group    = 1000
            capabilities {
              drop = ["ALL"]
            }
          }
        }

        security_context {
          run_as_non_root = true
          fs_group        = 1000
        }
      }
    }
  }
}

# Kubernetes service for Juice Shop
resource "kubernetes_service" "juice_shop" {
  metadata {
    name      = "${local.app_name}-app"
    namespace = kubernetes_namespace.quantumguard.metadata[0].name
  }

  spec {
    selector = {
      app = local.app_name
    }

    port {
      port        = 3000
      target_port = 3000
    }

    type = "ClusterIP"
  }
}

# Kubernetes deployment for Dashboard
resource "kubernetes_deployment" "dashboard" {
  metadata {
    name      = "${local.app_name}-dashboard"
    namespace = kubernetes_namespace.quantumguard.metadata[0].name
    labels = {
      app = "${local.app_name}-dashboard"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "${local.app_name}-dashboard"
      }
    }

    template {
      metadata {
        labels = {
          app = "${local.app_name}-dashboard"
        }
      }

      spec {
        container {
          name  = "dashboard"
          image = "quantumguard-dashboard:${local.image_tag}"

          port {
            container_port = 5000
          }

          env {
            name  = "FLASK_ENV"
            value = "production"
          }

          volume_mount {
            name       = "data-volume"
            mount_path = "/app/data"
          }

          volume_mount {
            name       = "reports-volume"
            mount_path = "/app/reports"
          }

          resources {
            limits = {
              cpu    = "300m"
              memory = "256Mi"
            }
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
          }

          security_context {
            run_as_non_root = true
            run_as_user     = 1000
            run_as_group    = 1000
            capabilities {
              drop = ["ALL"]
            }
          }
        }

        volume {
          name = "data-volume"
          host_path {
            path = "/opt/quantumguard/data"
          }
        }

        volume {
          name = "reports-volume"
          host_path {
            path = "/opt/quantumguard/reports"
          }
        }

        security_context {
          run_as_non_root = true
          fs_group        = 1000
        }
      }
    }
  }
}

# Kubernetes service for Dashboard
resource "kubernetes_service" "dashboard" {
  metadata {
    name      = "${local.app_name}-dashboard"
    namespace = kubernetes_namespace.quantumguard.metadata[0].name
  }

  spec {
    selector = {
      app = "${local.app_name}-dashboard"
    }

    port {
      port        = 5000
      target_port = 5000
    }

    type = "ClusterIP"
  }
}

# Network Policy for security
resource "kubernetes_network_policy" "quantumguard_policy" {
  metadata {
    name      = "quantumguard-network-policy"
    namespace = kubernetes_namespace.quantumguard.metadata[0].name
  }

  spec {
    pod_selector {}

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        pod_selector {}
      }
      ports {
        port     = "3000"
        protocol = "TCP"
      }
      ports {
        port     = "5000"
        protocol = "TCP"
      }
    }

    egress {
      to {}
      ports {
        port     = "53"
        protocol = "UDP"
      }
      ports {
        port     = "80"
        protocol = "TCP"
      }
      ports {
        port     = "443"
        protocol = "TCP"
      }
    }
  }
}

# ConfigMap for application configuration
resource "kubernetes_config_map" "quantumguard_config" {
  metadata {
    name      = "${local.app_name}-config"
    namespace = kubernetes_namespace.quantumguard.metadata[0].name
  }

  data = {
    "app-config.yaml" = <<-EOT
    app:
      name: ${local.app_name}
      environment: ${local.environment}
      port: 3000

    dashboard:
      port: 5000
      theme: cyberpunk

    security:
      enable_scanning: true
      scan_interval: 3600
      risk_threshold: 7.0
    EOT
  }
}

# Output values
output "juice_shop_url" {
  description = "URL for OWASP Juice Shop application"
  value       = "http://localhost:3000"
}

output "dashboard_url" {
  description = "URL for QuantumGuard Dashboard"
  value       = "http://localhost:5000"
}

output "kubernetes_namespace" {
  description = "Kubernetes namespace for QuantumGuard"
  value       = kubernetes_namespace.quantumguard.metadata[0].name
}
