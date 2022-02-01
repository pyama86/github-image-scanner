# frozen_string_literal: true

require './tests/test_helper'

class TestFuncks < Minitest::Test
  def test_scan_result_to_issue_md
    ret = {
      "ArtifactName" => "example.com/foo/bar:latest (debian 10.9)",
      "Results" => [
        {
          "Target" => "example.com/foo/bar:latest (debian 10.9)",
          "Class" => "os-pkgs",
          "Type" => "debian",
          "Vulnerabilities" => [
            {
              "VulnerabilityID" => "CVE-2020-8169",
              "PkgName" => "curl",
              "InstalledVersion" => "7.64.0-4+deb10u1",
              "FixedVersion" => "7.64.0-4+deb10u2",
              "PrimaryURL" => "https://avd.aquasec.com/nvd/cve-2020-8169",
              "Title" => "libcurl: partial password leak over DNS on HTTP redirect",
              "Description" => "curl 7.62.0 through 7.70.0 is vulnerable to an information disclosure vulnerability that can lead to a partial password being leaked over the network and to the DNS server(s).",
              "Severity" => "HIGH"
            },
            {
              "VulnerabilityID" => "CVE-2020-8177",
              "PkgName" => "curl",
              "InstalledVersion" => "7.64.0-4+deb10u1",
              "FixedVersion" => "7.64.0-4+deb10u2",
              "PrimaryURL" => "https://avd.aquasec.com/nvd/cve-2020-8177",
              "Title" => "curl:> Incorrect argument check can allow remote servers to overwrite local files",
              "Description" => "curl 7.20.0 through 7.70.0 is vulnerable to improper restriction of names for files and other resources that can lead too overwriting a local file when the -J flag is used.",
              "Severity" => "HIGH"
            }
          ]
        },
        {
          "Target" => "Ruby",
          "Class" => "lang-pkgs",
          "Type" => "gemspec",
          "Vulnerabilities" => [
            {
              "VulnerabilityID" => "CVE-2020-36327",
              "PkgName" => "bundler",
              "PkgPath" => "/usr/local/lib/ruby/gems/2.7.0/specifications/default/bundler-2.1.4.gemspec",
              "InstalledVersion" => "2.1.4",
              "FixedVersion" => "\u003e= 2.2.18, 2.2.10",
              "PrimaryURL" => "https://avd.aquasec.com/nvd/cve-2020-36327",
              "Title" => "rubygem-bundler: Dependencies of gems with explicit source may be installed from a different source",
              "Description" => "Bundler 1.16.0 through 2.2.9 and 2.2.11 through 2.2.16 sometimes chooses a dependency source based on the highest gem version number, which means that a rogue gem found at a public source may be chosen, even if the intended choice was a private gem that is a dependency of another private gem that is explicitly depended on by the application. NOTE: it is not correct to use CVE-2021-24105 for every \"Dependency Confusion\" issue in every product.",
              "Severity" => "HIGH"
            }
          ]
        }
      ]
    }

    cve_summary = {
      "CVE-2020-8169"=>
        {
          "Type"=>"debian",
          "PkgName"=>"libcurl4-openssl-dev",
          "PrimaryURL"=>"https://avd.aquasec.com/nvd/cve-2020-8169",
          "Artifacts"=> [
            "example.com/bar/foo:latest"
          ]
        }
    }
    ist, cve_summary = scan_result_to_issue_md(ret, cve_summary)
  end
end
