# DigitalOcean Debian to Arch Transformation using Terraform & Ansible

Transform your DigitalOcean Debian droplet into Arch Linux using automation tools like Terraform and Ansible. This guide uses the script and logic from [gh2o's digitalocean-debian-to-arch](https://github.com/gh2o/digitalocean-debian-to-arch). Special thanks to the contributors of that project!

## Warning / Disclaimer
> :warning: **ALL DATA ON THE DROPLET WILL BE UNCONDITIONALLY DESTROYED.**
>
> This transformation may cause your VPS to become unbootable. It's recommended to run this only on newly created droplets with no essential data.
---
## Infrastructure Setup Using Terraform

### Directory Structure:

digitalocean-terraform/
├── modules/
│ ├── droplet/
│ │ └── main.tf
│ └── networking/
│ └── main.tf
├── outputs.tf
├── main.tf
└── variables.tf
### Description:
- Terraform is utilized to provision the required infrastructure on DigitalOcean.
- Modules like `droplet` and `networking` ensure modularity and reusability in the Terraform configuration.
---
## Debian to Arch Transformation Using Ansible:

### Directory Structure:
digitalocean-debian-to-arch-ansible/
├── roles/
│ ├── prerequisites/
│ │ └── tasks/
│ │ └── main.yml
│ ├── download_script/
│ │ └── tasks/
│ │ └── main.yml
│ └── execute_script/
│ └── tasks/
│ └── main.yml
├── ansible.cfg
├── inventory.ini
└── transform.yml
### Description:
- Ansible is harnessed for configuration management and orchestration.
- The `roles` directory consists of tasks such as setting up prerequisites, downloading the transformation script, and executing it.
---
## Credits

This automation leverages the script and transformation logic from [gh2o's digitalocean-debian-to-arch](https://github.com/gh2o/digitalocean-debian-to-arch). All credits go to the contributors of that repository for the core transformation mechanism.
