data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023*-x86_64"]
  }
}

resource "aws_launch_template" "app" {
  name_prefix   = "${var.project_name}-lt-"
  image_id      = data.aws_ami.al2023.id
  instance_type = var.instance_type

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_profile.name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.ec2.id]
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh.tftpl", {
    aws_region        = var.aws_region
    s3_bucket         = aws_s3_bucket.artifacts.bucket
    db_password_param = aws_ssm_parameter.db_password.name
    gemini_key_param  = aws_ssm_parameter.gemini_api_key.name
    db_user           = aws_db_instance.main.username
    db_endpoint       = aws_db_instance.main.endpoint
    db_name           = aws_db_instance.main.db_name
    redis_host        = var.enable_elasticache ? aws_elasticache_cluster.redis[0].cache_nodes[0].address : ""
    log_group_name    = aws_cloudwatch_log_group.app.name
  }))

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.project_name}-ec2" }
  }
}

resource "aws_autoscaling_group" "app" {
  name                      = "${var.project_name}-asg"
  min_size                  = 2
  max_size                  = 3
  desired_capacity          = 2
  vpc_zone_identifier       = aws_subnet.public[*].id
  target_group_arns         = [aws_lb_target_group.app.arn]
  health_check_type         = "ELB"
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  instance_refresh {
    strategy = "Rolling"
  }

  depends_on = [aws_s3_object.app_bundle, aws_db_instance.main]
}
