provider "aws" {
      region = "ap-south-1"
      profile = "nandini_task1"
}


resource "tls_private_key" "mykey" {
algorithm = "RSA"
}


resource "local_file" "privatekey" {
content = tls_private_key.mykey.private_key_pem
filename = "mykey.pem"
file_permission = 0400
}


resource "aws_key_pair" "resource_key" {
key_name = "publickey" 
public_key = tls_private_key.mykey.public_key_openssh

depends_on = [
tls_private_key.mykey ]
}


resource "aws_security_group" "allow_rules" {
  name      = "allow_rules"
  description = "Allow inbound traffic ie SSH and HTTP"
  vpc_id      = "vpc-938096fb"


ingress {
    description = "Inbound HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Inbound SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Allow_securityrules"
  }
}


resource "aws_instance" "Nandini_os1"  {
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  availability_zone = "ap-south-1a"
  key_name      = aws_key_pair.resource_key.key_name
  security_groups = ["allow_rules"]

  tags = {
    Name = "Nandini_os1"
  }
    }



resource "aws_ebs_volume" "mypd1" {
  availability_zone = "ap-south-1a"
  size              = 2
  
  tags = {
    Name = "myvol1"
  }
}

resource "aws_volume_attachment" "attach_pd1" {

  depends_on = [
    aws_ebs_volume.mypd1,
  ]
 device_name = "/dev/sdn"
  volume_id   = aws_ebs_volume.mypd1.id
  instance_id = aws_instance.Nandini_os1.id
  force_detach = true
}


resource "null_resource" "nullremote"  {

depends_on = [
   local_file.privatekey, tls_private_key.mykey, aws_volume_attachment.attach_pd1, 
 ]

 connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.mykey.private_key_pem
    host     = aws_instance.Nandini_os1.public_ip
  }


provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd -y",
      "sudo yum install git -y",
      "sudo systemctl start httpd",
      "sudo mkfs.ext4  /dev/xvdn",
      "sudo mount  /dev/xvdn  /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/blisss13/Hybrid_Multi_Cloud_Task1.git /var/www/html"
    ]
  }
}



resource "aws_s3_bucket" "unique_bkt1" {
  bucket = "nandinibkt1"
  acl    = "public-read"
  force_destroy = true

provisioner "local-exec" {
 command  = "git clone https://github.com/blisss13/Hybrid_Multi_Cloud_Task1.git server_img"
   }

 provisioner "local-exec" {
  when =  destroy
command = "rmdir /s /q server_img"
}
   tags = {
    Name = "mys3bkt1"
  }
}

resource "aws_s3_bucket_object" "imageupload" {

 depends_on = [
    aws_s3_bucket.unique_bkt1,
]
  bucket  = aws_s3_bucket.unique_bkt1.bucket
  key     = "Path.jpg"
  source  = "server_img/Path.jpg"
  acl     = "public-read"
}

locals {
  s3_origin_id = "S3-${aws_s3_bucket.unique_bkt1.bucket}"
}


resource "aws_cloudfront_distribution" "my_terra_cloudfront" {
  origin {
    domain_name = "nandinibkt1.s3.amazonaws.com"
    origin_id   = "S3-nandinibkt1"

        custom_origin_config {
            http_port = 80
            https_port = 80
         origin_protocol_policy = "match-viewer"
            origin_ssl_protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"]
        }
    }
  enabled = true
  is_ipv6_enabled = true

  default_cache_behavior {
  allowed_methods = [ "GET", "HEAD", "OPTIONS"]
  cached_methods = ["GET", "HEAD"]
  target_origin_id = "S3-nandinibkt1"

  forwarded_values {
    query_string = false

    cookies {
      forward = "none"
      }
    }
   viewer_protocol_policy = "allow-all"
  min_ttl = 0
  default_ttl = 3600
  max_ttl = 86400
}
    restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}






