package templates

// Fail renders the general failure page and user feedback.
var Fail = `
{{ define "content" }}

<br><br>
<div class="center">
	<h1>{{ .StatusCode }}: {{ .StatusText }}</h1>
	<div style="color: red; font-weight: bold">
		{{ .Message }}
	</div>
</div>


{{ end }}
`
