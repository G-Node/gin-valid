package templates

// PubValidate renders the public validation page. Validations for public repositories
// on the companion GIN service can be requested via this page.
// Hardcoded validators support BIDS, NIX and odML validation.
var PubValidate = `
{{ define "content" }}
	<div class="user signin">
		<form class="ui form" action="/pubvalidate" method="post">
			<h4 class="ui top attached segment">
				Enter the full name of a GIN repository (user/repository) below and select a validator to run:
			</h4>
			<div class="ui attached segment">
			{{ if .ErrorMessage }}
				<div class="ui message red">{{ .ErrorMessage }}</div>
			{{ end }}
				<div class="required inline field left">
					<label for="repopath">Repository name</label>
					<input id="repopath" name="repopath" value="" autofocus required>
					<button class="ui green button right">Submit</button>
				</div>
			</div>
			<div class="ui attached segment">
			<div class="ui segment field">
				<h4>Validators</h4>
				<div class="inline field">
					<div class="ui radio checkbox">
						<input name="validator" value="bids" type="radio" checked="checked">
						<label><strong>BIDS</strong> Brain Imaging Data Structure: link-to-bids-website</label>
					</div>
				</div>
				<div class="inline field">
					<div class="ui radio checkbox">
						<input name="validator" value="nix" type="radio">
						<label><strong>NIX</strong> Neuroscience Information Exchange format link-to-nix-website</label>
					</div>
				</div>
				<div class="inline field">
					<div class="ui radio checkbox">
						<input name="validator" value="odml" type="radio">
						<label><strong>odML</strong> Open Metadata Markup Language link-to-odml-website</label>
					</div>
				</div>
			</div>
			</div>
			<div class="ui attached segment">
				Alternatively, you can <a href="/login">login</a> using your GIN account to set up automatic validation of your public and private repositories.
			</div>
		</form>
	</div>
{{ end }}
`
