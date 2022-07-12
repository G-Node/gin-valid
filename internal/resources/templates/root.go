package templates

// Root displays a basic validation form.
var Root = `
{{ define "content" }}

<br><br>
<hr>
Enter the full name of a GIN repository (user/repository) below and select a validator to run:
<div>
    <form action="/pubvalidate" method="post">
    <p>Repository name: <input type="text" name="repopath"></p>
    </form>
</div>

<hr>
Alternatively, you can <a href="/login">login</a> using your GIN account to set up automatic validation of your public and private repositories.

{{ end }}
`
