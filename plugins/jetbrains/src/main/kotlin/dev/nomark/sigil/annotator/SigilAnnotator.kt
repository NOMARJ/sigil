package dev.nomark.sigil.annotator

import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.editor.Editor
import com.intellij.psi.PsiFile
import dev.nomark.sigil.runner.ScanFinding
import dev.nomark.sigil.runner.SigilRunner
import dev.nomark.sigil.settings.SigilSettings

class SigilAnnotator : ExternalAnnotator<PsiFile, List<ScanFinding>>() {

    override fun collectInformation(file: PsiFile, editor: Editor, hasErrors: Boolean): PsiFile? {
        val settings = SigilSettings.getInstance(file.project)
        if (!settings.autoScanOnSave) return null
        return file
    }

    override fun doAnnotate(file: PsiFile?): List<ScanFinding> {
        file ?: return emptyList()
        val virtualFile = file.virtualFile ?: return emptyList()
        return try {
            val runner = SigilRunner(file.project)
            runner.scan(virtualFile.path).findings
        } catch (_: Exception) {
            emptyList()
        }
    }

    override fun apply(file: PsiFile, findings: List<ScanFinding>, holder: AnnotationHolder) {
        val document = file.viewProvider.document ?: return

        for (finding in findings) {
            val line = (finding.line ?: 1) - 1
            if (line < 0 || line >= document.lineCount) continue

            val startOffset = document.getLineStartOffset(line)
            val endOffset = document.getLineEndOffset(line)

            val severity = when (finding.severity.lowercase()) {
                "critical", "high" -> HighlightSeverity.ERROR
                "medium" -> HighlightSeverity.WARNING
                else -> HighlightSeverity.WEAK_WARNING
            }

            holder.newAnnotation(severity, "[${finding.rule}] ${finding.snippet}")
                .range(startOffset, endOffset)
                .tooltip("Sigil: ${finding.phase} — ${finding.snippet}")
                .create()
        }
    }
}
