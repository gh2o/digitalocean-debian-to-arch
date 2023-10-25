variable "do_token" {
  description = "DigitalOcean API Token"
  type        = string
}

variable "droplet_name" {
  description = "Name of the droplet to be created"
  type        = string
  default     = "debian-to-arch-droplet"
}

variable "region" {
  description = "Region for the droplet"
  type        = string
  default     = "nyc3"
}

variable "ssh_key_id" {
  description = "SSH Key ID for accessing the droplet"
  type        = string
}

variable "image_name" {
  description = "Image name for the droplet"
  type        = string
  default     = "debian-10-x64"
}

variable "size" {
  description = "Droplet size"
  default     = "s-1vcpu-1gb"
}
