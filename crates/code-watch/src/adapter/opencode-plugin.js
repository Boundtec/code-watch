// code-watch managed plugin
const ARGV = __ARGV__
const FAIL_OPEN = __FAIL_OPEN__

export const CodeWatch = async ({ directory }) => ({
  "tool.execute.before": async (input, output) => {
    if (input.tool !== "bash") return
    let reason
    try {
      const proc = Bun.spawn(ARGV, { stdin: "pipe", stdout: "pipe", stderr: "inherit" })
      proc.stdin.write(JSON.stringify({ command: output.args.command, cwd: directory }))
      proc.stdin.end()
      const text = await new Response(proc.stdout).text()
      const code = await proc.exited
      if (code !== 0) throw new Error("code-watch exited with code " + code)
      if (text.trim() === "") return
      const reply = JSON.parse(text)
      if (reply.decision !== "deny") return
      reason = String(reply.reason || "code-watch denied this command")
    } catch (e) {
      if (FAIL_OPEN) return
      reason = "code-watch could not check this command: " + e.message
    }
    throw new Error(reason)
  },
})
