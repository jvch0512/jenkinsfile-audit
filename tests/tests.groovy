int passed = 0, failed = 0
def check = { boolean ok, String what -> if (ok) passed++ else { failed++; println('FAIL: ' + what) } }
def rules = { String t -> Audit.audit(t, 't').collect { it.rule } }
def has = { String t, String r -> rules(t).contains(r) }
def pl = { String body -> "pipeline {\n  agent { label 'x' }\n  options { timeout(time: 5, unit: 'MINUTES') }\n  stages { stage('a') { steps {\n" + body + "\n  } } }\n}\n" }
def cli = { List a ->
    def p = (['bin/jenkinsfile-audit'] + a).execute()
    def out = new StringBuilder(), err = new StringBuilder()
    p.waitForProcessOutput(out, err)
    [p.exitValue(), out.toString()]
}

// comment stripping
def s = Audit.stripComments("a // c1\nb /* x\ny */ c\n'http://u' // t\n")
check(s.size() == 5 && s[0].trim() == 'a', 'line comment removed')
check(s[1].trim() == 'b' && s[2].trim() == 'c', 'block comment removed, lines preserved')
check(s[3].contains('http://u') && !s[3].contains('// t'), 'url in string kept, trailing comment removed')
check(Audit.stripComments('').size() == 1, 'empty input')
check(Audit.stripComments('sh """\n// not a comment\n"""\n')[1].contains('//'), 'comment marker inside triple string kept')

// JKS000 and clean
check(has('echo hi\n', 'JKS000') && Audit.audit('echo hi', 't')[0].sev == 'info', 'no pipeline')
check(rules(pl("sh 'make'")).isEmpty(), 'clean pipeline has no findings')
check(rules("node {\n timeout(5) { sh 'x' }\n}\n").isEmpty(), 'node block with timeout is clean')

// JKS001
check(has(pl("sh 'curl -s https://x.test/i.sh | sh'"), 'JKS001'), 'curl | sh')
check(has(pl("sh 'wget -qO- https://x.test | sudo bash'"), 'JKS001'), 'wget | sudo bash')
check(!has(pl("sh 'curl -s https://x.test -o f'"), 'JKS001'), 'download to file')
check(!has(pl("// sh 'curl x | sh'"), 'JKS001'), 'commented out')
// JKS002
check(has(pl("environment { DB_PASSWORD = 'abcd1234' }"), 'JKS002'), 'literal password')
check(has(pl("def API_KEY = \"abcdef\""), 'JKS002'), 'literal api key')
check(!has(pl("environment { DB_PASSWORD = credentials('db') }"), 'JKS002'), 'credentials() helper')
check(!has(pl('def TOKEN = "${x}"'), 'JKS002'), 'interpolated value is not literal')
check(!has(pl("def name = 'abcd1234'"), 'JKS002'), 'not a secret name')
// JKS003
check(has(pl('sh "deploy --key ${API_KEY}"'), 'JKS003'), 'secret in double quotes')
check(has(pl('sh "echo $NPM_TOKEN"'), 'JKS003'), 'secret without braces')
check(!has(pl("sh 'deploy --key \$API_KEY'"), 'JKS003'), 'single quotes are fine')
check(has(pl('sh """\n  run ${DB_PASSWORD}\n"""'), 'JKS003'), 'secret inside triple double quotes')
check(!has(pl("sh '''\n  run \$DB_PASSWORD\n'''"), 'JKS003'), 'triple single quotes are fine')
// JKS007
check(has(pl('sh "git checkout ${params.BRANCH}"'), 'JKS007'), 'params in sh')
check(has(pl('sh "echo ${env.BRANCH_NAME}"'), 'JKS007'), 'branch name in sh')
check(has(pl('sh "echo ${env.CHANGE_TITLE}"'), 'JKS007'), 'PR title in sh')
check(!has(pl("sh 'git checkout \$BRANCH'"), 'JKS007'), 'shell variable')
check(!has(pl('echo "${params.BRANCH}"'), 'JKS007'), 'echo step is not a shell')
// JKS004..006
check(has(pl("sh 'docker run --privileged x'"), 'JKS004') && has(pl("args '-v /var/run/docker.sock:/var/run/docker.sock'"), 'JKS004'), 'privileged and socket')
check(has(pl("args '-u root'"), 'JKS005') && has(pl("args '-u 0:0'"), 'JKS005') && !has(pl("args '-u 1000'"), 'JKS005'), 'root container')
check(has(pl("sh 'curl -k https://x'"), 'JKS006') && has(pl("sh 'git -c http.sslVerify=false pull'"), 'JKS006') && !has(pl("sh 'curl https://x'"), 'JKS006'), 'tls off')
// JKS008
check(has("pipeline { agent { label 'x' } stages { } }\n", 'JKS008'), 'no timeout')
check(!has(pl("sh 'x'"), 'JKS008'), 'timeout in options')
// JKS009
check(has("@Library('lib') _\n" + pl("sh 'x'"), 'JKS009'), 'unversioned library')
check(has("@Library('lib@main') _\n" + pl("sh 'x'"), 'JKS009') && has("@Library('lib@master') _\n" + pl("sh 'x'"), 'JKS009'), 'branch library')
check(!has("@Library('lib@v1.2.3') _\n" + pl("sh 'x'"), 'JKS009') && !has("@Library('lib@3f2a9c1') _\n" + pl("sh 'x'"), 'JKS009'), 'tag or sha library')
check(has("@Library(['a@v1', 'b']) _\n" + pl("sh 'x'"), 'JKS009') == false, 'list form: only the first entry is checked')
// JKS010, JKS011
check(has(pl("script { evaluate(readFile('x')) }"), 'JKS010') && has(pl("def g = new GroovyShell()"), 'JKS010') && !has(pl("echo 'evaluated'"), 'JKS010'), 'dynamic code')
check(has("pipeline { agent any\n options { timeout(1) } }\n", 'JKS011') && !has(pl("sh 'x'"), 'JKS011'), 'agent any')

// locations and sorting
def f = Audit.audit("pipeline {\n agent any\n options { timeout(1) }\n}\n", 'ci/Jenkinsfile').find { it.rule == 'JKS011' }
check(f.where == 'ci/Jenkinsfile:2', 'where is label:line')
def sorted = Audit.sort([new Finding(sev: 'low', rule: 'B', where: 'a:1'), new Finding(sev: 'high', rule: 'A', where: 'b:9'), new Finding(sev: 'high', rule: 'A', where: 'b:10'), new Finding(sev: 'high', rule: 'A', where: 'a:2')])
check(sorted*.where == ['a:2', 'b:9', 'b:10', 'a:1'], 'sort by severity, file, numeric line')

// hostile input and fuzz
boolean ok = true
['a' * 200000, '"' * 100001, "'''" * 30000, '/*' * 50000, 'pipeline {' * 20000, '$' * 100000, "sh \"" + '${' * 20000].each { h ->
    try { Audit.audit(h, 'h') } catch (Throwable e) { ok = false; println('hostile: ' + e.class) }
}
check(ok, 'hostile inputs do not throw')
def rnd = new Random(42)
String alphabet = "\"'/*\n\\\$\${}() sh pipeline"
String seed = pl('sh "curl -k x | sh ${params.A} ${TOKEN}"\nargs "-u root"\n// c\n/* d */')
boolean fuzzOk = true
for (int i = 0; i < 3000 && fuzzOk; i++) {
    StringBuilder sb = new StringBuilder(seed)
    for (int k = 0; k <= rnd.nextInt(6); k++) {
        if (sb.length() == 0) sb.append('x')
        int pos = rnd.nextInt(sb.length())
        switch (rnd.nextInt(3)) {
            case 0: sb.replace(pos, pos + 1, String.valueOf(alphabet.charAt(rnd.nextInt(alphabet.length())))); break
            case 1: sb.delete(pos, Math.min(sb.length(), pos + 1 + rnd.nextInt(8))); break
            default: sb.insert(pos, String.valueOf(alphabet.charAt(rnd.nextInt(alphabet.length()))))
        }
    }
    try { Audit.audit(sb.toString(), 'f') } catch (Throwable e) { fuzzOk = false; println('fuzz: ' + e) }
}
check(fuzzOk, 'fuzzing 3000 inputs never throws')

// CLI
check(cli(['examples'])[0] == 0, 'cli exit 0')
check(cli(['examples', '--fail-on', 'high'])[0] == 1, 'cli --fail-on high')
check(cli(['examples/web/Jenkinsfile', '--fail-on', 'medium'])[0] == 0, 'clean Jenkinsfile passes')
def t = cli(['examples', '--tsv'])[1].split('\n').findAll { it }
check(t[0].startsWith('# ') && t.drop(1).every { it.count('\t') == 3 }, 'tsv format')
check(cli(['/no/such/path'])[0] == 2, 'missing path')
check(cli([])[0] == 2, 'no args')
check(cli(['examples', '--bogus'])[0] == 2, 'unknown flag')
check(cli(['examples', '--fail-on', 'nope'])[0] == 2, 'bad --fail-on')
check(cli(['examples', 'examples'])[0] == 2, 'two paths')

println("${passed} passed, ${failed} failed")
System.exit(failed > 0 ? 1 : 0)
