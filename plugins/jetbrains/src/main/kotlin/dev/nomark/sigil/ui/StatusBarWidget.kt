package dev.nomark.sigil.ui

import com.intellij.openapi.actionSystem.ActionPlaces
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.DataContext
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.Disposer
import com.intellij.openapi.wm.StatusBar
import com.intellij.openapi.wm.StatusBarWidget
import com.intellij.openapi.wm.StatusBarWidgetFactory
import dev.nomark.sigil.actions.ScanProjectAction
import java.awt.event.MouseEvent
import java.util.function.Consumer

class SigilStatusBarWidget(private val project: Project) : StatusBarWidget, StatusBarWidget.TextPresentation {

    override fun ID(): String = "SigilStatusBar"

    override fun getText(): String = "Sigil"

    override fun getTooltipText(): String = "Run Sigil security scan"

    override fun getClickConsumer(): Consumer<MouseEvent>? = Consumer {
        val action = ScanProjectAction()
        val dataContext = DataContext { dataId ->
            when (dataId) {
                CommonDataKeys.PROJECT.name -> project
                else -> null
            }
        }
        val anEvent = AnActionEvent.createFromDataContext(
            ActionPlaces.STATUS_BAR_PLACE,
            action.templatePresentation.clone(),
            dataContext
        )
        action.actionPerformed(anEvent)
    }

    override fun getPresentation(): StatusBarWidget.WidgetPresentation = this

    override fun install(statusBar: StatusBar) {}

    override fun dispose() {}
}

class SigilStatusBarWidgetFactory : StatusBarWidgetFactory {
    override fun getId(): String = "SigilStatusBar"

    override fun getDisplayName(): String = "Sigil Security Scanner"

    override fun isAvailable(project: Project): Boolean = true

    override fun createWidget(project: Project): StatusBarWidget = SigilStatusBarWidget(project)

    override fun disposeWidget(widget: StatusBarWidget) = Disposer.dispose(widget)

    override fun canBeEnabledOn(statusBar: StatusBar): Boolean = true
}
