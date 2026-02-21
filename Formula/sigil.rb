# Homebrew Formula for Sigil
# This file should be copied to: https://github.com/NOMARJ/homebrew-tap/Formula/sigil.rb

class Sigil < Formula
  desc "Automated security auditing for AI agent code"
  homepage "https://sigilsec.ai"
  url "https://github.com/NOMARJ/sigil/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "" # Will be auto-filled by release workflow
  license "Apache-2.0"
  version "1.0.5"

  # Pre-built binaries
  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/NOMARJ/sigil/releases/download/v0.1.0/sigil-macos-arm64.tar.gz"
      sha256 "" # Will be auto-filled by release workflow
    else
      url "https://github.com/NOMARJ/sigil/releases/download/v0.1.0/sigil-macos-x64.tar.gz"
      sha256 "" # Will be auto-filled by release workflow
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/NOMARJ/sigil/releases/download/v0.1.0/sigil-linux-aarch64.tar.gz"
      sha256 "" # Will be auto-filled by release workflow
    else
      url "https://github.com/NOMARJ/sigil/releases/download/v0.1.0/sigil-linux-x64.tar.gz"
      sha256 "" # Will be auto-filled by release workflow
    end
  end

  # Build from source (fallback)
  depends_on "rust" => :build

  def install
    # If using pre-built binary
    if build.bottle?
      bin.install "sigil"
    else
      # Build from source
      cd "cli" do
        system "cargo", "build", "--release"
        bin.install "target/release/sigil"
      end
    end

    # Install shell completions (future)
    # bash_completion.install "completions/sigil.bash"
    # zsh_completion.install "completions/_sigil"
    # fish_completion.install "completions/sigil.fish"
  end

  def post_install
    # Run sigil install to set up shell aliases
    system "#{bin}/sigil", "install" rescue nil
  end

  test do
    # Verify the binary runs
    assert_match "SIGIL", shell_output("#{bin}/sigil --version")

    # Test scan on a safe test file
    (testpath/"test.py").write("print('hello')")
    system "#{bin}/sigil", "scan", testpath/"test.py"
  end

  service do
    # Future: daemon mode for continuous scanning
    # run [opt_bin/"sigil", "daemon"]
    # keep_alive true
    # log_path var/"log/sigil.log"
    # error_log_path var/"log/sigil-error.log"
  end
end
