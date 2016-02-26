# cPanel Security Advisor README

The cPanel Security Advisor analyzes the configuration of a cPanel & WHM system to make recommendations that improve system security.

## Installation

Installing from the GitHub repository is only needed if you want to contribute to the development of the security advisor, or you simply want the latest changes before they are distributed with cPanel & WHM. To install from here, you need to clone the repository, then run the installer.

 1. /usr/local/cpanel/3rdparty/bin/git clone https://github.com/Cpanelinc/addon_securityadvisor.git
 2. cd addon_securityadvisor/pkg
 3. ./install

The next time cPanel & WHM updates it will over write your changes. To keep the GitHub version you need to create a *postupcp* hook that re-runs the installer at the end of the update.

## Usage

The Security Advisor is found within the Security Center of WHM. It requires root privileges to access. There are two ways to find the Advisor.

 1. Log into WHM with root privileges
 2. Click Security Center
 3. Click Security Advisor

OR

 1. Log into WHM with root privileges
 2. Search for Security Advisor
 3. Click Security Advisor

Accessing the Security Advisor begins the analysis of your system.

## License

See the LICENSE file in the project root directory.

## Contributing

Contributions are welcome. Please use contribute using [GitHub Flow](https://guides.github.com/introduction/flow/). Create a branch, add commits, and [open a pull request](https://github.com/cpanelinc/addon_securityadvisor/compare/).

