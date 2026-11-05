package it.snel.passkeychain.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Brand: deep indigo link + warm key-gold accent (matches the logo).
private val Indigo = Color(0xFF4F46E5)
private val IndigoDark = Color(0xFF3730A3)
private val Gold = Color(0xFFF2B705)
private val Ink = Color(0xFF14121F)

private val Light = lightColorScheme(
    primary = Indigo,
    onPrimary = Color.White,
    secondary = Gold,
    onSecondary = Ink,
    tertiary = IndigoDark,
)

private val Dark = darkColorScheme(
    primary = Color(0xFF9B93FF),
    onPrimary = Ink,
    secondary = Gold,
    onSecondary = Ink,
    tertiary = Color(0xFFB8B2FF),
)

@Composable
fun PassKeyChainTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (dark) Dark else Light, content = content)
}
