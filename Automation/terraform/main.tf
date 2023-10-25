terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "2.28.1"
    }
  }
}

provider "digitalocean" {
  token = var.do_token
}

resource "digitalocean_ssh_key" "my_key" {
  name       = "my-ssh-key"
  public_key = file("~/.ssh/id_rsa.pub")
}



resource "digitalocean_droplet" "debian_droplet" {
  name     = var.droplet_name
  size     = var.size
  region   = var.region
  image    = var.image_name
  ssh_keys = [digitalocean_ssh_key.my_key.id]

  tags = ["debian-to-arch"]

}

# resource "digitalocean_firewall" "public_internet" {
#   name = "public-internet"
#   inbound_rule {
#     protocol   = "tcp"
#     port_range = "0-65535"
#   }
# }
