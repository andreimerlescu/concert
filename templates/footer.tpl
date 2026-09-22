{{define "footer"}}
</main>
<footer class="border-top py-3 small text-body-secondary">
  <div class="container-fluid d-flex flex-wrap justify-content-between gap-2">
    <span>Concert {{.Version}}</span>
    <span>FIFO waiting room reverse proxy · built on room and sema</span>
  </div>
</footer>
<div class="toast-container position-fixed bottom-0 end-0 p-3" id="toasts"></div>
<script src="/assets/{{.BootstrapJS}}"></script>
<script src="/assets/{{.PortalJS}}"></script>
</body>
</html>
{{end}}