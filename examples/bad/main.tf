resource "aws_security_group" "db" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "exports" {
  bucket = "shop-exports"
}

resource "aws_db_instance" "orders" {
  engine = "postgres"
}

resource "aws_cloudwatch_log_group" "app" {
  name = "/shop/app"
}

resource "aws_ebs_volume" "data" {
  size = 50
}
