{ pkgs, perSystem }:
perSystem.devshell.mkShell {
  packages = [
    perSystem.self.restate-bin

    # go
    pkgs.gcc
    pkgs.go
    pkgs.golangci-lint
    pkgs.goreleaser
    pkgs.syft

    # other
    perSystem.self.formatter
    pkgs.just
    pkgs.modd
    pkgs.okteto
  ];

  env = [
    {
      name = "NIX_PATH";
      value = "nixpkgs=${toString pkgs.path}";
    }
    {
      name = "NIX_DIR";
      eval = "$PRJ_ROOT/nix";
    }
  ];

  commands = [
    {
      name = "k";
      category = "ops";
      help = "Shorter alias for kubectl";
      command = ''${pkgs.kubectl}/bin/kubectl "$@"'';
    }
    {
      name = "kvs";
      category = "Ops";
      help = "kubectl view-secret alias";
      command = ''${pkgs.kubectl-view-secret}/bin/kubectl-view-secret "$@"'';
    }
    {
      name = "kns";
      category = "ops";
      help = "Switch kubernetes namespaces";
      command = ''kubens "$@"'';
    }
  ];
}
