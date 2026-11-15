class Audit {
    static final Map RANK = [critical: 0, high: 1, medium: 2, low: 3, info: 4]

    /** Blanks out // and block comments but keeps line numbers. Strings are respected. */
    static List<String> stripComments(String text) {
        StringBuilder out = new StringBuilder()
        int n = text.length()
        int i = 0
        char quote = 0
        boolean triple = false
        boolean block = false
        while (i < n) {
            char c = text.charAt(i)
            if (block) {
                if (c == (char) '*' && i + 1 < n && text.charAt(i + 1) == (char) '/') { block = false; i += 2; continue }
                out.append(c == (char) '\n' ? '\n' : ' ')
                i++
                continue
            }
            if (quote != 0) {
                out.append(c)
                if (c == (char) '\\' && i + 1 < n) { out.append(text.charAt(i + 1)); i += 2; continue }
                if (c == quote) {
                    if (triple) {
                        if (i + 2 < n && text.charAt(i + 1) == quote && text.charAt(i + 2) == quote) {
                            out.append(quote).append(quote); i += 3; quote = 0; triple = false; continue
                        }
                    } else { quote = 0 }
                } else if (c == (char) '\n' && !triple) { quote = 0 }
                i++
                continue
            }
            if (c == (char) '/' && i + 1 < n && text.charAt(i + 1) == (char) '/' && (i == 0 || Character.isWhitespace(text.charAt(i - 1)) || text.charAt(i - 1) == (char) ';')) {
                while (i < n && text.charAt(i) != (char) '\n') i++
                continue
            }
            if (c == (char) '/' && i + 1 < n && text.charAt(i + 1) == (char) '*') { block = true; out.append("  "); i += 2; continue }
            if (c == (char) '"' || c == (char) "'") {
                quote = c
                triple = i + 2 < n && text.charAt(i + 1) == c && text.charAt(i + 2) == c
                out.append(c)
                if (triple) { out.append(c).append(c); i += 2 }
                i++
                continue
            }
            out.append(c)
            i++
        }
        return out.toString().split("\r\n|\n|\r", -1).toList()
    }

    static final def PIPE_SHELL = ~/(?i)\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/
    static final def SECRET_NAME = '(?i)[A-Za-z_]*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)[A-Za-z_]*'
    static final def LITERAL_SECRET = ~('(' + SECRET_NAME + ')\\s*=\\s*[\'"]([^\'"$\\s][^\'"]{3,})[\'"]')
    static final def INTERP_SECRET = ~('\\$\\{?\\s*(env\\.|params\\.)?(' + SECRET_NAME + ')\\s*\\}?')
    static final def INTERP_USER = ~/\$\{?\s*(params\.\w+|env\.(BRANCH_NAME|CHANGE_TITLE|CHANGE_BRANCH|CHANGE_AUTHOR)|CHANGE_TITLE|BRANCH_NAME)\s*\}?/
    static final def INSECURE = ~/(?i)(\bcurl\b[^\n]*\s(-k|--insecure)\b|--no-check-certificate|http\.sslVerify=false|strict-ssl\s+false|NODE_TLS_REJECT_UNAUTHORIZED=0|GIT_SSL_NO_VERIFY)/

    static List<Finding> audit(String text, String label) {
        List<Finding> out = []
        List<String> lines = stripComments(text)
        def add = { String sev, String rule, int ln, String msg -> out << new Finding(sev: sev, rule: rule, where: label + ':' + ln, msg: msg) }
        boolean pipeline = lines.any { it =~ /\b(pipeline|node)\s*(\(.*\))?\s*\{/ }
        if (!pipeline) return [new Finding(sev: 'info', rule: 'JKS000', where: label + ':1', msg: 'no pipeline or node block found')]
        boolean inInterp = false      // inside a """ string
        boolean hasTimeout = false
        lines.eachWithIndex { String line, int idx ->
            int ln = idx + 1
            int tripleDouble = (line =~ /"""/).count
            boolean interpLine = inInterp || line =~ /\b(sh|bat|script)\s*(\(\s*)?"/ || line =~ /\b(sh|bat)\s*\(?\s*script\s*:\s*"/
            if (line =~ /\btimeout\s*\(/ || line =~ /\btimeout\s*time\s*:/) hasTimeout = true
            if (PIPE_SHELL.matcher(line).find()) add('high', 'JKS001', ln, 'remote script piped into a shell: the pipeline runs whatever the server returns')
            def m = LITERAL_SECRET.matcher(line)
            if (m.find()) add('high', 'JKS002', ln, 'literal secret assigned to ' + m.group(1) + ': use Jenkins credentials')
            if (interpLine && INTERP_SECRET.matcher(line).find() && line =~ /\$/) {
                add('high', 'JKS003', ln, 'credential interpolated in a double-quoted shell string: use single quotes and let the shell read the variable')
            }
            if (interpLine && INTERP_USER.matcher(line).find()) {
                add('high', 'JKS007', ln, 'user-controlled value interpolated in a double-quoted shell string: command injection through parameters or branch names')
            }
            if (line =~ /--privileged\b/ || line =~ /docker\.sock/) add('medium', 'JKS004', ln, 'privileged container or Docker socket: the build can take over the host')
            if (line =~ /(?i)-u\s+(root|0)(\s|'|"|:|$)/ || line =~ /--user[= ]+(root|0)\b/) add('medium', 'JKS005', ln, 'container runs as root')
            if (INSECURE.matcher(line).find()) add('medium', 'JKS006', ln, 'TLS verification is disabled')
            def lib = line =~ /@Library\(\s*(\[?\s*)?['"]([^'"]+)['"]/
            if (lib.find()) {
                String spec = lib.group(2)
                if (!spec.contains('@')) add('medium', 'JKS009', ln, 'shared library ' + spec + ' has no version: it follows whatever the default branch is')
                else {
                    String ver = spec.substring(spec.indexOf('@') + 1)
                    if (ver in ['main', 'master', 'develop', 'dev', 'HEAD', 'trunk']) add('medium', 'JKS009', ln, 'shared library pinned to branch ' + ver + ': pin a tag or commit')
                }
            }
            if (line =~ /\b(evaluate\s*\(|Eval\.me\s*\(|GroovyShell)/) add('medium', 'JKS010', ln, 'dynamic code evaluation')
            if (line =~ /\bagent\s+any\b/) add('low', 'JKS011', ln, 'agent any: the job can land on any node, including the controller')
            if (tripleDouble % 2 == 1) inInterp = !inInterp
        }
        if (!hasTimeout) add('low', 'JKS008', 1, 'no timeout: a stuck build holds an executor forever')
        return out
    }

    static List<Finding> sort(List<Finding> f) {
        return f.sort(false) { a, b ->
            int r = RANK[a.sev] <=> RANK[b.sev]
            if (r != 0) return r
            String fa = a.where.substring(0, a.where.lastIndexOf(':')), fb = b.where.substring(0, b.where.lastIndexOf(':'))
            r = fa <=> fb
            if (r != 0) return r
            int la = a.where.substring(a.where.lastIndexOf(':') + 1) as int, lb = b.where.substring(b.where.lastIndexOf(':') + 1) as int
            r = la <=> lb
            return r != 0 ? r : a.rule <=> b.rule
        }
    }
}
