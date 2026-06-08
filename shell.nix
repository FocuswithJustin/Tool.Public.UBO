{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    go               # 1.26.x latest
    wireguard-tools  # wg, wg-quick, wg-genkey, wg-pubkey
    openssh          # ssh-keygen, ssh
    gnumake
    gopls
    gotools
    qemu             # qemu-system-x86_64, qemu-img — integration test VM
    wget             # download Debian cloud image
    xorriso          # create cloud-init seed ISO
  ];
}
