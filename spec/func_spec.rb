describe 'func' do
  let(:result) {
    testdata("trivy-results/result.json")
  }
  describe '#scan_result_to_issue_md' do
    describe 'Return values test' do
      it 'include vulnerability markdown table in issue text' do
        expected_text = "|os|debian|bsdutils|-|2.36.1-8|2.36.1-8+deb11u1|[CVE-2021-3995](https://avd.aquasec.com/nvd/cve-2021-3995)|\n|os|debian|bsdutils|-|2.36.1-8|2.36.1-8+deb11u1|[CVE-2021-3996](https://avd.aquasec.com/nvd/cve-2021-3996)|"
        issue_txt, = scan_result_to_issue_md(result, {}, [])
        expect(issue_txt).to include(expected_text)
      end

      it 'include vulnerability summary in cve_summary' do
        expected_cve = "CVE-2021-3995"
        _, cve_summary = scan_result_to_issue_md(result, {}, [])
        expect(cve_summary).to have_key(expected_cve)
      end

      describe 'interface test' do
        let(:cve_summary) {
          _, cve_summary = scan_result_to_issue_md(result, {}, [])
          cve_summary["CVE-2021-3995"]
        }

        it 'has Artifacts' do
          expect(cve_summary).to have_key("Artifacts")
        end

        it 'has PkgName' do
          expect(cve_summary).to have_key("PkgName")
        end

        it 'has PrimaryURL' do
          expect(cve_summary).to have_key("PrimaryURL")
        end

        it 'has Type' do
          expect(cve_summary).to have_key("Type")
        end
      end

      describe 'ignore vulnerabilities' do
        let(:ignore_vulnerabilities) { ['CVE-2021-3995'] }

        it 'do not include ignored vulnerabilities in issue text' do
          issue_txt, cve_summary = scan_result_to_issue_md(result, {}, ignore_vulnerabilities)
          expect(issue_txt).not_to include('CVE-2021-3995')
        end

        it 'do include not ignored vulnerabilities in issue_txt' do
          issue_txt, cve_summary = scan_result_to_issue_md(result, {}, ignore_vulnerabilities)
          expect(issue_txt).to include('CVE-2021-3996')
        end

        it 'do not include ignored vulnerabilities in cve summary' do
          issue_txt, cve_summary = scan_result_to_issue_md(result, {}, ignore_vulnerabilities)
          expect(cve_summary).not_to have_key('CVE-2021-3995')
        end

        it 'do include not ignored vulnerabilities in cve_summary' do
          issue_txt, cve_summary = scan_result_to_issue_md(result, {}, ignore_vulnerabilities)
          expect(cve_summary).to have_key('CVE-2021-3996')
        end
      end
    end
  end

  describe '#cve_summary_md' do
    let(:cve_summary) {
      _, cve_summary = scan_result_to_issue_md(result, {}, [])
      cve_summary
    }

    it 'to be markdown table' do
      expect(cve_summary_md(cve_summary)).to include('|[CVE-2021-3995](https://avd.aquasec.com/nvd/cve-2021-3995)|uuid-dev|python:3.6|')
    end
  end
end
