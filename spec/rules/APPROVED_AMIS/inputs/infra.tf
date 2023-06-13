provider "aws" {
  region = "us-east-2"
}

resource "aws_vpc" "vpc" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"
}

resource "aws_subnet" "subnet" {
  vpc_id     = aws_vpc.vpc.id
  cidr_block = "10.0.0.0/24"
}

resource "aws_instance" "valid" {
  ami           = "ami-04581fbf744a7d11f"
  instance_type = "t3.nano"
  subnet_id     = aws_subnet.subnet.id
}

resource "aws_instance" "invalid" {
  ami           = "ami-00eeedc4036573771"
  instance_type = "t3.nano"
}
