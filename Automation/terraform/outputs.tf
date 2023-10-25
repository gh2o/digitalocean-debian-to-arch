output "droplet_ip" {
  value = digitalocean_droplet.debian_droplet.ipv4_address
}
