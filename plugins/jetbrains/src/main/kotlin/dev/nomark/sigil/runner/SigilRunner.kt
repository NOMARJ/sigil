package dev.nomark.sigil.runner

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.google.gson.reflect.TypeToken
import com.intellij.openapi.project.Project
import dev.nomark.sigil.settings.SigilSettings
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit

data class QuarantineItem(
    val id: String = "",
    val source: String = "",
    @SerializedName("source_type")
    val sourceType: String = "",
    val status: String = "",
    @SerializedName("scan_score")
    val scanScore: Double? = null
)

data class ScanFinding(
    val phase: String = "",
    val rule: String = "",
    val severity: String = "",
    val file: String = "",
    val line: Int? = null,
    val snippet: String = "",
    val weight: Int = 1
)

data class ScanResult(
    val verdict: String = "",
    val score: Int = 0,
    @SerializedName("files_scanned")
    val filesScanned: Int = 0,
    val findings: List<ScanFinding> = emptyList(),
    @SerializedName("duration_ms")
    val durationMs: Long = 0
)

class SigilRunner(private val project: Project) {
    private val gson = Gson()

    fun scan(path: String): ScanResult {
        val settings = SigilSettings.getInstance(project)
        val args = mutableListOf(settings.binaryPath, "--format", "json", "scan", path)

        if (settings.phases.isNotBlank()) {
            args.addAll(listOf("--phases", settings.phases))
        }
        if (settings.severityThreshold != "low") {
            args.addAll(listOf("--severity", settings.severityThreshold))
        }

        return execute(args)
    }

    fun scanPackage(manager: String, packageName: String): ScanResult {
        val settings = SigilSettings.getInstance(project)
        val args = mutableListOf(settings.binaryPath, "--format", "json", manager, packageName)
        return execute(args)
    }

    fun clearCache() {
        val settings = SigilSettings.getInstance(project)
        val process = ProcessBuilder(settings.binaryPath, "clear-cache")
            .redirectErrorStream(true)
            .start()
        process.waitFor(30, TimeUnit.SECONDS)
    }

    fun listQuarantine(): List<QuarantineItem> {
        val settings = SigilSettings.getInstance(project)
        val process = ProcessBuilder(settings.binaryPath, "list", "--format", "json")
            .redirectErrorStream(false)
            .start()

        val stdout = BufferedReader(InputStreamReader(process.inputStream)).readText()
        val completed = process.waitFor(60, TimeUnit.SECONDS)

        if (!completed) {
            process.destroyForcibly()
            throw RuntimeException("Sigil list timed out")
        }

        if (stdout.isBlank()) {
            return emptyList()
        }

        val listType = object : TypeToken<List<QuarantineItem>>() {}.type
        return gson.fromJson(stdout, listType) ?: emptyList()
    }

    fun approveItem(id: String): Boolean {
        val settings = SigilSettings.getInstance(project)
        val process = ProcessBuilder(settings.binaryPath, "approve", id)
            .redirectErrorStream(true)
            .start()
        val completed = process.waitFor(30, TimeUnit.SECONDS)
        return completed && process.exitValue() == 0
    }

    fun rejectItem(id: String): Boolean {
        val settings = SigilSettings.getInstance(project)
        val process = ProcessBuilder(settings.binaryPath, "reject", id)
            .redirectErrorStream(true)
            .start()
        val completed = process.waitFor(30, TimeUnit.SECONDS)
        return completed && process.exitValue() == 0
    }

    private fun execute(args: List<String>): ScanResult {
        val process = ProcessBuilder(args)
            .redirectErrorStream(false)
            .start()

        val stdout = BufferedReader(InputStreamReader(process.inputStream)).readText()
        val completed = process.waitFor(300, TimeUnit.SECONDS)

        if (!completed) {
            process.destroyForcibly()
            throw RuntimeException("Sigil scan timed out after 5 minutes")
        }

        if (stdout.isBlank()) {
            val stderr = BufferedReader(InputStreamReader(process.errorStream)).readText()
            throw RuntimeException("Sigil returned no output: $stderr")
        }

        return gson.fromJson(stdout, ScanResult::class.java)
    }
}
