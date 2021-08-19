# github-image-scanner

config.ymlに指定した情報に基づき、Organizationのリポジトリに登録されたイメージをスキャンします。

## 利用方法
config.yml.sampleを参考に、必要な情報を定義します。

```yaml
registory_domain: docker.pkg.github.com  # コンテナイメージのドメイン
orgs:
- pyama86  # 検査対象のOrganization

ignore_images:
- example.com/foo/bar:latest # 検査を除外するイメージ(正規表現)
```

あとはActionsで下記のように実行してください。

```yaml
name: scan
on:
  push:
    branches:
      - 'master'
jobs:
  container:
    runs-on: ubuntu-latest
    env:
      GITHUB_USER: "your name"
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      GITHUB_API: "https://api.github.com/"
      RUBYOPT: "-W0"
    container:
      image: pyama/github-image-scanner:latest
    steps:
      - name: checkout
        uses: actions/checkout@v2

      - name: Cache Trivy
        uses: actions/cache@v2
        with:
          path: |
            /opt/scanner/cache
          key: ${{ runner.os }}
          restore-keys: |
            ${{ runner.os }}


      - run: |
          cp config.yml.sample /opt/scanner/config.yml
          cd /opt/scanner
          bundle exec ruby run.rb
```

正常にすれば、自動で検査し、必要に応じてissueが作成されます。
