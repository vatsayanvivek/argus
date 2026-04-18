# Homebrew formula for ARGUS.
#
# Usage (via the personal tap):
#   brew tap vatsayanvivek/argus https://github.com/vatsayanvivek/argus
#   brew install argus
#
# Version + SHA256 placeholders are replaced at release time by
# scripts/package-managers/update-homebrew.sh using SHA256SUMS from the
# matching GitHub release.

class Argus < Formula
  desc "Agentless, offline Azure CSPM + attack-chain analyser"
  homepage "https://github.com/vatsayanvivek/argus"
  version "__VERSION__"
  license "PolyForm-Strict-1.0.0"

  on_macos do
    on_arm do
      url "https://github.com/vatsayanvivek/argus/releases/download/v#{version}/argus-darwin-arm64"
      sha256 "__SHA256_DARWIN_ARM64__"
    end
    on_intel do
      url "https://github.com/vatsayanvivek/argus/releases/download/v#{version}/argus-darwin-amd64"
      sha256 "__SHA256_DARWIN_AMD64__"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vatsayanvivek/argus/releases/download/v#{version}/argus-linux-arm64"
      sha256 "__SHA256_LINUX_ARM64__"
    end
    on_intel do
      url "https://github.com/vatsayanvivek/argus/releases/download/v#{version}/argus-linux-amd64"
      sha256 "__SHA256_LINUX_AMD64__"
    end
  end

  def install
    bin.install Dir["argus-*"].first => "argus"
  end

  test do
    assert_match "ARGUS", shell_output("#{bin}/argus --version")
  end
end
