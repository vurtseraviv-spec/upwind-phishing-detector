variable "aws_region" {
  description = "AWS Region for deployment"
  type        = string
  default     = "eu-north-1"
}

variable "project_name" {
  description = "Prefix for all AWS resources"
  type        = string
  default     = "phishing-detector"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "db_instance_class" {
  description = "RDS instance type"
  type        = string
  default     = "db.t3.micro"
}

variable "enable_elasticache" {
  description = "Deploy ElastiCache Redis (Bonus)"
  type        = bool
  default     = true
}

variable "gemini_api_key" {
  description = "Optional Google Gemini API key for live AI investigation & analyst chat (stored securely in SSM)"
  type        = string
  default     = ""
  sensitive   = true
}
