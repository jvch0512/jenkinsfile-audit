def usage() {
    System.err.println('usage: jenkinsfile-audit PATH [--tsv] [--fail-on medium|high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.')
    return 2
}

def isJenkinsfile(String n) {
    String l = n.toLowerCase()
    return l == 'jenkinsfile' || l.startsWith('jenkinsfile.') || l.endsWith('.jenkinsfile')
}

def run(String[] args) {
    String path = null
    boolean tsv = false
    String failOn = null
    int i = 0
    while (i < args.length) {
        String a = args[i]
        if (a == '--tsv') tsv = true
        else if (a == '--fail-on') {
            i++
            if (i >= args.length || !(args[i] in ['medium', 'high', 'critical'])) return usage()
            failOn = args[i]
        } else if (a.startsWith('-')) return usage()
        else if (path != null) return usage()
        else path = a
        i++
    }
    if (path == null) return usage()
    File root = new File(path)
    if (!root.exists()) { System.err.println('error: no such file or directory: ' + path); return 2 }
    List files = []
    if (root.isDirectory()) {
        def base = root.getAbsoluteFile().toPath()
        root.eachFileRecurse { f -> if (f.isFile() && isJenkinsfile(f.name)) files << [base.relativize(f.getAbsoluteFile().toPath()).toString().replace('\\', '/'), f] }
        files.sort { it[0] }
    } else files << [root.name, root]
    List all = []
    files.each { pair -> if (pair[1].length() <= 4000000) all.addAll(Audit.audit(new String(pair[1].bytes, 'UTF-8'), pair[0])) }
    def sorted = Audit.sort(all)
    String head = files.size() + ' files, ' + sorted.size() + ' findings'
    println(tsv ? '# ' + head : head)
    sorted.each { f ->
        if (tsv) println([f.sev, f.rule, f.where, f.msg].join('\t'))
        else { println(String.format('%-8s %s %s', f.sev.toUpperCase(), f.rule, f.where)); println('         ' + f.msg) }
    }
    if (failOn != null && sorted.any { Audit.RANK[it.sev] <= Audit.RANK[failOn] }) return 1
    return 0
}

System.exit(run(args))
