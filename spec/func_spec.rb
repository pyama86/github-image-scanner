describe 'func' do
  describe '#scan_result_to_issue_md' do
    let(:result) {
      testdata("trivy-results/result.json")
    }

    before {
      object = Object.new
      allow(object).to receive(:scan_image).and_return(result)
    }

    describe 'Return values test' do
      it 'include vulnerability markdown table in issue text' do
        expected_text = "|os|debian|bsdutils|-|2.36.1-8|2.36.1-8+deb11u1|[CVE-2021-3995](https://avd.aquasec.com/nvd/cve-2021-3995)|\n|os|debian|bsdutils|-|2.36.1-8|2.36.1-8+deb11u1|[CVE-2021-3996](https://avd.aquasec.com/nvd/cve-2021-3996)|"
        issue_txt, = scan_result_to_issue_md(result, {})
        expect(issue_txt).to include(expected_text)
      end

      it 'include vulnerability summary in cve_summary' do
        expected_cve = "CVE-2021-3995"
        _, cve_summary = scan_result_to_issue_md(result, {})
        expect(cve_summary).to have_key(expected_cve)
      end

      describe 'interface test' do
        let(:cve) { "CVE-2021-3995" }

        it 'has Artifacts' do
          _, cve_summary = scan_result_to_issue_md(result, {})
          expect(cve_summary[cve]).to have_key("Artifacts")
        end

        it 'has PkgName' do
          _, cve_summary = scan_result_to_issue_md(result, {})
          expect(cve_summary[cve]).to have_key("PkgName")
        end

        it 'has PrimaryURL' do
          _, cve_summary = scan_result_to_issue_md(result, {})
          expect(cve_summary[cve]).to have_key("PrimaryURL")
        end

        it 'has Type' do
          _, cve_summary = scan_result_to_issue_md(result, {})
          expect(cve_summary[cve]).to have_key("Type")
        end
      end
    end
  end
end
