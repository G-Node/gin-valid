package templates

// BidsResults renders the result content of BIDS validations.
const BidsResults = `
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
	{{ range $val := .Issues.Errors }}
	<hr>
	<div>
		{{ $val.Severity }}, {{ $val.Key }}
	</div>
	<div>
		Reason: {{ $val.Reason }}
	</div>
	<div>
		{{ range $file := $val.Files }}
		<div>Filename: {{ $file.File.Name }} (Code: {{ $file.Code }})</div>
		<div>Path: {{ $file.File.Path }}</div>
		{{ end }}
	</div>
	{{ end }}

	{{ range $val := .Issues.Warnings }}
	<hr>
	<div>
		{{ $val.Severity }}, {{ $val.Key }}
	</div>
	<div>
		Reason: {{ $val.Reason }}
	</div>
	<div>
		{{ range $file := $val.Files }}
		<div>Filename: {{ $file.File.Name }} (Code: {{ $file.Code }})</div>
		<div>Path: {{ $file.File.Path }}</div>
		{{ end }}
	</div>
	{{ end }}

{{ if .ErrorMessage }}
	<div class="ui message red">
		{{ .ErrorMessage }}
	</div>
{{ end }}

{{ if .Summary }}
	<div>Summary</div>
	<div>Sessions: {{ .Summary.Sessions }}</div>
	<div>Subjects: {{ .Summary.Subjects }}</div>
	<div>Tasks: {{ .Summary.Tasks }}</div>
	<div>Modalities: {{ .Summary.Modalities }}</div>
	<div>Total files: {{ .Summary.TotalFiles }}</div>
	<div>Size: {{ .Summary.Size }}</div>
{{ end }}
		</div>
		</div>
		</div>
	</div>
{{end}}
`
