package it.snel.passkeychain.ui

import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation

/** The eye button at the end of a password field: shows or hides what was typed. */
@Composable
fun ShowPasswordButton(shown: Boolean, onToggle: () -> Unit) {
    IconButton(onClick = onToggle) {
        Icon(if (shown) AppIcons.VisibilityOff else AppIcons.Visibility, if (shown) "Hide password" else "Show password")
    }
}

/** Dots, or the password itself when [shown]. */
fun passwordLook(shown: Boolean): VisualTransformation = if (shown) VisualTransformation.None else PasswordVisualTransformation()
