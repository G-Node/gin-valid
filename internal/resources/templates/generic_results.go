package templates

// GenericResults is a template that requires only a header text, a badge, and
// content. The content is displayed in a <pre> block.
const GenericResults = `
{{define "content"}}
	<div class="repository file list">
		<div class="header-wrapper">
			<div class="ui container">
				<div class="ui vertically padded grid head">
					<div class="column">
						<div class="ui header">
							<div class="ui huge breadcrumb">
								<i class="mega-octicon octicon-repo"></i>
								{{.Header}}
								{{.Badge}}
							</div>
						</div>
					</div>
				</div>
			</div>
			<div class="ui tabs container">
			</div>
			<div class="ui tabs divider"></div>
		</div>
		<div class="ui container">
		<div class="ui grid">
		<div class="column" style="width:20%">
			<div id="history">History:</div>
			{{ range $val := .Results }}
			<div>
				<a href="{{$val.Href}}" alt="{{$val.Alt}}">
					{{$val.Badge}}<br>
					<span class="tiny">{{$val.Text1}} {{$val.Text2}}</span>
				</a>
			</div>
			{{ end }}
		</div>
		<div class="column" style="width:80%">
			{{ if not (eq .LoadingSVG "") }}
			<div class="center" style="width: 100px; height: 100px; margin: auto;">
				{{ .LoadingSVG }}
			</div>
			{{ end }}
			<hr>
			<div>
				<pre style="white-space: pre-wrap">{{.Content}}</pre>
			</div>
		</div>
		</div>
		</div>
	</div>
{{end}}
`
