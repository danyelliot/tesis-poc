# Reporte de Vulnerabilidades en GitHub Actions Workflows

**Fecha**: 2025-04-26 21:25:25

**Total de vulnerabilidades encontradas**: 118

Este informe ha sido generado automáticamente para detectar patrones de vulnerabilidad en flujos de trabajo de GitHub Actions.
Las vulnerabilidades identificadas representan riesgos potenciales que deberían ser validados y mitigados según su contexto específico.

## Resumen Ejecutivo

### Distribución por Severidad

```
Alta:   (1)
Media: ████████████ (45)
Baja:  ████████████████████ (72)
```

### Distribución por Tipo de Vulnerabilidad

- **Undefined Permissions**: 41 ocurrencias
- **Undefined Token Permissions**: 31 ocurrencias
- **Excessive Permissions**: 30 ocurrencias
- **Unsafe Action Reference**: 15 ocurrencias
- **Script Injection**: 1 ocurrencias

## Análisis Detallado por Tipo de Vulnerabilidad

### Undefined Permissions (41 ocurrencias)

**Descripción**: Workflow sin permisos explícitamente definidos

**Severidad**: Baja

**Impacto Potencial**: Sin una definición explícita de permisos, el workflow usará los permisos predeterminados del repositorio, que generalmente incluyen acceso de escritura al contenido. Esto puede otorgar más permisos de los necesarios, ampliando la superficie de ataque.

**Vector de Explotación**: El token GITHUB_TOKEN con permisos implícitos podría ser utilizado por acciones comprometidas para realizar operaciones no deseadas en el repositorio.

**Recomendación General**: 
Definir explícitamente permisos mínimos al inicio del workflow:
```yaml
permissions: read-all  # Establece todos los permisos como solo lectura
```
Luego otorgar permisos específicos sólo donde sea necesario.

**Referencias y Recursos**:

- https://docs.github.com/es/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token
- https://github.blog/changelog/2021-04-20-github-actions-permission-options-for-the-github_token/
- https://github.blog/2023-02-02-enabling-fine-grained-permissions-github-actions-enterprise/

#### Ocurrencias Específicas

<details>
<summary>Ocurrencia 1 - .github/workflows/test.yml</summary>

**Ubicación**: .github/workflows/test.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 2 - .github/workflows/checkin.yml</summary>

**Ubicación**: .github/workflows/checkin.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 3 - .github/workflows/test.yml</summary>

**Ubicación**: .github/workflows/test.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 4 - .github/workflows/codeql-analysis.yml</summary>

**Ubicación**: .github/workflows/codeql-analysis.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 5 - .github/workflows/node.js.yml</summary>

**Ubicación**: .github/workflows/node.js.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 6 - .github/workflows/check-dist.yml</summary>

**Ubicación**: .github/workflows/check-dist.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 7 - .github/workflows/codeql-analysis.yml</summary>

**Ubicación**: .github/workflows/codeql-analysis.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 8 - .github/workflows/test.yml</summary>

**Ubicación**: .github/workflows/test.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 9 - .github/workflows/deploy-staging.yml</summary>

**Ubicación**: .github/workflows/deploy-staging.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 10 - .github/workflows/all_tests.yaml</summary>

**Ubicación**: .github/workflows/all_tests.yaml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 11 - .github/workflows/annotations.yml</summary>

**Ubicación**: .github/workflows/annotations.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 12 - .github/workflows/called.yml</summary>

**Ubicación**: .github/workflows/called.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 13 - .github/workflows/checks-workflows.yml</summary>

**Ubicación**: .github/workflows/checks-workflows.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 14 - .github/workflows/docker_tests.yml</summary>

**Ubicación**: .github/workflows/docker_tests.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 15 - .github/workflows/env-exps.yml</summary>

**Ubicación**: .github/workflows/env-exps.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 16 - .github/workflows/exportable_workflow.yaml</summary>

**Ubicación**: .github/workflows/exportable_workflow.yaml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 17 - .github/workflows/test-deploy.yml</summary>

**Ubicación**: .github/workflows/test-deploy.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 18 - .github/workflows/test-regressions.yml</summary>

**Ubicación**: .github/workflows/test-regressions.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 19 - .github/workflows/test.yaml</summary>

**Ubicación**: .github/workflows/test.yaml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 20 - .github/workflows/format.yml</summary>

**Ubicación**: .github/workflows/format.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 21 - .github/workflows/lint.yml</summary>

**Ubicación**: .github/workflows/lint.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 22 - .github/workflows/publint.yml</summary>

**Ubicación**: .github/workflows/publint.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 23 - .github/workflows/test.yml</summary>

**Ubicación**: .github/workflows/test.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 24 - .github/workflows/build-test-deploy.yml</summary>

**Ubicación**: .github/workflows/build-test-deploy.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 25 - .github/workflows/hello-world.yml</summary>

**Ubicación**: .github/workflows/hello-world.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 26 - .github/workflows/check-dist.yml</summary>

**Ubicación**: .github/workflows/check-dist.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 27 - .github/workflows/label-sync.yaml</summary>

**Ubicación**: .github/workflows/label-sync.yaml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 28 - .github/workflows/test.yml</summary>

**Ubicación**: .github/workflows/test.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 29 - .github/workflows/auto-assign.yml</summary>

**Ubicación**: .github/workflows/auto-assign.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 30 - .github/workflows/example.yml</summary>

**Ubicación**: .github/workflows/example.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 31 - .github/workflows/label-checker.yml</summary>

**Ubicación**: .github/workflows/label-checker.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 32 - .github/workflows/task-list-checker.yml</summary>

**Ubicación**: .github/workflows/task-list-checker.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 33 - .github/workflows/test-workflow.yml</summary>

**Ubicación**: .github/workflows/test-workflow.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 34 - .github/workflows/blank.yml</summary>

**Ubicación**: .github/workflows/blank.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 35 - .github/workflows/ci.yml</summary>

**Ubicación**: .github/workflows/ci.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 36 - .github/workflows/ci.yml</summary>

**Ubicación**: .github/workflows/ci.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 37 - .github/workflows/ci.yaml</summary>

**Ubicación**: .github/workflows/ci.yaml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 38 - .github/workflows/ruby-push.yml</summary>

**Ubicación**: .github/workflows/ruby-push.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 39 - .github/workflows/ruby-push.yml</summary>

**Ubicación**: .github/workflows/ruby-push.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 40 - .github/workflows/blank.yml</summary>

**Ubicación**: .github/workflows/blank.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

<details>
<summary>Ocurrencia 41 - .github/workflows/main.yml</summary>

**Ubicación**: .github/workflows/main.yml, línea 0

**Código vulnerable**:
```yaml
No se encontró cláusula 'permissions:' en el workflow
```

</details>

### Undefined Token Permissions (31 ocurrencias)

**Descripción**: Uso de GITHUB_TOKEN sin permisos explícitamente definidos

**Severidad**: Baja

**Impacto Potencial**: El token está utilizando permisos predeterminados que podrían ser excesivos para la operación que se está realizando.

**Vector de Explotación**: Una acción comprometida podría usar el token con permisos más amplios de los necesarios para la tarea específica.

**Recomendación General**: 
Definir permisos explícitos para el job o el paso que utiliza el token:
```yaml
jobs:
  example_job:
    permissions:
      issues: write
      contents: read
```

**Referencias y Recursos**:

- https://docs.github.com/es/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token
- https://github.blog/changelog/2021-04-20-github-actions-permission-options-for-the-github_token/

#### Ocurrencias Específicas

<details>
<summary>Ocurrencia 1 - .github/workflows/0-welcome.yml</summary>

**Ubicación**: .github/workflows/0-welcome.yml, línea 66

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 2 - .github/workflows/1-create-beta-release.yml</summary>

**Ubicación**: .github/workflows/1-create-beta-release.yml, línea 60

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 3 - .github/workflows/2-feature-added-to-release.yml</summary>

**Ubicación**: .github/workflows/2-feature-added-to-release.yml, línea 60

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 4 - .github/workflows/3-release-pr-opened.yml</summary>

**Ubicación**: .github/workflows/3-release-pr-opened.yml, línea 60

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 5 - .github/workflows/4-release-notes-and-merge.yml</summary>

**Ubicación**: .github/workflows/4-release-notes-and-merge.yml, línea 65

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 6 - .github/workflows/5-finalize-release.yml</summary>

**Ubicación**: .github/workflows/5-finalize-release.yml, línea 67

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 7 - .github/workflows/6-commit-hotfix.yml</summary>

**Ubicación**: .github/workflows/6-commit-hotfix.yml, línea 65

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 8 - .github/workflows/7-create-hotfix-release.yml</summary>

**Ubicación**: .github/workflows/7-create-hotfix-release.yml, línea 60

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 9 - .github/workflows/label-sync.yaml</summary>

**Ubicación**: .github/workflows/label-sync.yaml, línea 16

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 10 - .github/workflows/0-welcome.yml</summary>

**Ubicación**: .github/workflows/0-welcome.yml, línea 88

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 11 - .github/workflows/1-create-a-workflow.yml</summary>

**Ubicación**: .github/workflows/1-create-a-workflow.yml, línea 68

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 12 - .github/workflows/2-add-a-job.yml</summary>

**Ubicación**: .github/workflows/2-add-a-job.yml, línea 68

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 13 - .github/workflows/3-add-actions.yml</summary>

**Ubicación**: .github/workflows/3-add-actions.yml, línea 68

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 14 - .github/workflows/4-merge-your-pull-request.yml</summary>

**Ubicación**: .github/workflows/4-merge-your-pull-request.yml, línea 61

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 15 - .github/workflows/5-trigger.yml</summary>

**Ubicación**: .github/workflows/5-trigger.yml, línea 63

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 16 - .github/workflows/0-welcome.yml</summary>

**Ubicación**: .github/workflows/0-welcome.yml, línea 88

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 17 - .github/workflows/1-create-the-workflow-file.yml</summary>

**Ubicación**: .github/workflows/1-create-the-workflow-file.yml, línea 70

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 18 - .github/workflows/2-add-a-dockerfile.yml</summary>

**Ubicación**: .github/workflows/2-add-a-dockerfile.yml, línea 70

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 19 - .github/workflows/3-merge-your-pull-request.yml</summary>

**Ubicación**: .github/workflows/3-merge-your-pull-request.yml, línea 61

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 20 - .github/workflows/0-welcome.yml</summary>

**Ubicación**: .github/workflows/0-welcome.yml, línea 61

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 21 - .github/workflows/1-add-a-test-workflow.yml</summary>

**Ubicación**: .github/workflows/1-add-a-test-workflow.yml, línea 70

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 22 - .github/workflows/2-fix-the-test.yml</summary>

**Ubicación**: .github/workflows/2-fix-the-test.yml, línea 64

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 23 - .github/workflows/3-upload-test-reports.yml</summary>

**Ubicación**: .github/workflows/3-upload-test-reports.yml, línea 70

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 24 - .github/workflows/4-add-branch-protections.yml</summary>

**Ubicación**: .github/workflows/4-add-branch-protections.yml, línea 70

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 25 - .github/workflows/5-merge-your-pull-request.yml</summary>

**Ubicación**: .github/workflows/5-merge-your-pull-request.yml, línea 62

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 26 - .github/workflows/0-welcome.yml</summary>

**Ubicación**: .github/workflows/0-welcome.yml, línea 61

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 27 - .github/workflows/1-add-a-test-workflow.yml</summary>

**Ubicación**: .github/workflows/1-add-a-test-workflow.yml, línea 70

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 28 - .github/workflows/2-fix-the-test.yml</summary>

**Ubicación**: .github/workflows/2-fix-the-test.yml, línea 64

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 29 - .github/workflows/3-upload-test-reports.yml</summary>

**Ubicación**: .github/workflows/3-upload-test-reports.yml, línea 70

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 30 - .github/workflows/4-add-branch-protections.yml</summary>

**Ubicación**: .github/workflows/4-add-branch-protections.yml, línea 70

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

<details>
<summary>Ocurrencia 31 - .github/workflows/5-merge-your-pull-request.yml</summary>

**Ubicación**: .github/workflows/5-merge-your-pull-request.yml, línea 62

**Código vulnerable**:
```yaml
token: ${{ secrets.GITHUB_TOKEN }}
```

</details>

### Excessive Permissions (30 ocurrencias)

**Descripción**: El workflow tiene permisos de escritura completos sobre el repositorio

**Severidad**: Media

**Impacto Potencial**: Los permisos de escritura sobre el contenido del repositorio permiten a las acciones modificar código, crear commits, y potencialmente introducir código malicioso. Si una acción es comprometida, podría modificar archivos críticos o eludir protecciones.

**Vector de Explotación**: Un actor malicioso que comprometa una de las acciones o scripts utilizados podría aprovechar estos permisos para introducir backdoors, modificar archivos de configuración, o agregar dependencias maliciosas que se propagarían a la aplicación o a futuras ejecuciones.

**Recomendación General**: 
1. Seguir el principio de mínimo privilegio - usar 'permissions: read-all' por defecto
2. Otorgar permisos específicos sólo para los recursos necesarios
3. Limitar los permisos de escritura a scopes específicos (ej: issues: write) en lugar de contents
4. Considerar el uso de trabajos (jobs) separados con diferentes niveles de permiso

**Referencias y Recursos**:

- https://docs.github.com/es/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token
- https://docs.github.com/es/actions/security-guides/security-hardening-for-github-actions#considering-cross-repository-access
- https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
- https://github.blog/2021-04-19-how-we-use-and-secure-github-actions-at-github/

#### Ocurrencias Específicas

<details>
<summary>Ocurrencia 1 - .github/workflows/0-welcome.yml</summary>

**Ubicación**: .github/workflows/0-welcome.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 2 - .github/workflows/1-create-beta-release.yml</summary>

**Ubicación**: .github/workflows/1-create-beta-release.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 3 - .github/workflows/2-feature-added-to-release.yml</summary>

**Ubicación**: .github/workflows/2-feature-added-to-release.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 4 - .github/workflows/3-release-pr-opened.yml</summary>

**Ubicación**: .github/workflows/3-release-pr-opened.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 5 - .github/workflows/4-release-notes-and-merge.yml</summary>

**Ubicación**: .github/workflows/4-release-notes-and-merge.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 6 - .github/workflows/5-finalize-release.yml</summary>

**Ubicación**: .github/workflows/5-finalize-release.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 7 - .github/workflows/6-commit-hotfix.yml</summary>

**Ubicación**: .github/workflows/6-commit-hotfix.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 8 - .github/workflows/7-create-hotfix-release.yml</summary>

**Ubicación**: .github/workflows/7-create-hotfix-release.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 9 - .github/workflows/0-welcome.yml</summary>

**Ubicación**: .github/workflows/0-welcome.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 10 - .github/workflows/1-create-a-workflow.yml</summary>

**Ubicación**: .github/workflows/1-create-a-workflow.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 11 - .github/workflows/2-add-a-job.yml</summary>

**Ubicación**: .github/workflows/2-add-a-job.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 12 - .github/workflows/3-add-actions.yml</summary>

**Ubicación**: .github/workflows/3-add-actions.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 13 - .github/workflows/4-merge-your-pull-request.yml</summary>

**Ubicación**: .github/workflows/4-merge-your-pull-request.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 14 - .github/workflows/5-trigger.yml</summary>

**Ubicación**: .github/workflows/5-trigger.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 15 - .github/workflows/0-welcome.yml</summary>

**Ubicación**: .github/workflows/0-welcome.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 16 - .github/workflows/1-create-the-workflow-file.yml</summary>

**Ubicación**: .github/workflows/1-create-the-workflow-file.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 17 - .github/workflows/2-add-a-dockerfile.yml</summary>

**Ubicación**: .github/workflows/2-add-a-dockerfile.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 18 - .github/workflows/3-merge-your-pull-request.yml</summary>

**Ubicación**: .github/workflows/3-merge-your-pull-request.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 19 - .github/workflows/0-welcome.yml</summary>

**Ubicación**: .github/workflows/0-welcome.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 20 - .github/workflows/1-add-a-test-workflow.yml</summary>

**Ubicación**: .github/workflows/1-add-a-test-workflow.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 21 - .github/workflows/2-fix-the-test.yml</summary>

**Ubicación**: .github/workflows/2-fix-the-test.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 22 - .github/workflows/3-upload-test-reports.yml</summary>

**Ubicación**: .github/workflows/3-upload-test-reports.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 23 - .github/workflows/4-add-branch-protections.yml</summary>

**Ubicación**: .github/workflows/4-add-branch-protections.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 24 - .github/workflows/5-merge-your-pull-request.yml</summary>

**Ubicación**: .github/workflows/5-merge-your-pull-request.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 25 - .github/workflows/0-welcome.yml</summary>

**Ubicación**: .github/workflows/0-welcome.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 26 - .github/workflows/1-add-a-test-workflow.yml</summary>

**Ubicación**: .github/workflows/1-add-a-test-workflow.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 27 - .github/workflows/2-fix-the-test.yml</summary>

**Ubicación**: .github/workflows/2-fix-the-test.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 28 - .github/workflows/3-upload-test-reports.yml</summary>

**Ubicación**: .github/workflows/3-upload-test-reports.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 29 - .github/workflows/4-add-branch-protections.yml</summary>

**Ubicación**: .github/workflows/4-add-branch-protections.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

<details>
<summary>Ocurrencia 30 - .github/workflows/5-merge-your-pull-request.yml</summary>

**Ubicación**: .github/workflows/5-merge-your-pull-request.yml, línea 0

**Código vulnerable**:
```yaml
permissions: contents: write
```

</details>

### Unsafe Action Reference (15 ocurrencias)

**Descripción**: Acción referenciada sin versión específica

**Severidad**: Media

**Impacto Potencial**: Si la acción se actualiza con cambios maliciosos o tiene vulnerabilidades, el workflow automáticamente usará la nueva versión sin verificación, permitiendoejecución de código no auditado en tu flujo de trabajo.

**Vector de Explotación**: Ejemplo: Un atacante podría hacer un fork de la acción referenciada, obtener control del repositorio original mediante ingeniería social o vulnerabilidades, y luego modificar la acción para exfiltrar secretos o comprometer el entorno de CI/CD.

**Recomendación General**: 
Especificar un hash SHA completo (40 caracteres) para la referencia de la acción. Por ejemplo, en lugar de `actions/checkout@v2`, usar `actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675`.

**Referencias y Recursos**:

- https://docs.github.com/es/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions
- https://blog.aquasec.com/github-actions-security-supply-chain
- https://securitylab.github.com/research/github-actions-untrusted-input/
- https://docs.github.com/es/actions/creating-actions/about-custom-actions#using-release-management-for-actions

#### Ocurrencias Específicas

<details>
<summary>Ocurrencia 1 - .github/workflows/test.yml</summary>

**Ubicación**: .github/workflows/test.yml, línea 30

**Código vulnerable**:
```yaml
uses: ./
```

</details>

<details>
<summary>Ocurrencia 2 - .github/workflows/test.yml</summary>

**Ubicación**: .github/workflows/test.yml, línea 36

**Código vulnerable**:
```yaml
uses: ./
```

</details>

<details>
<summary>Ocurrencia 3 - .github/workflows/test.yml</summary>

**Ubicación**: .github/workflows/test.yml, línea 40

**Código vulnerable**:
```yaml
uses: ./
```

</details>

<details>
<summary>Ocurrencia 4 - .github/workflows/test.yml</summary>

**Ubicación**: .github/workflows/test.yml, línea 47

**Código vulnerable**:
```yaml
uses: ./
```

</details>

<details>
<summary>Ocurrencia 5 - .github/workflows/test.yml</summary>

**Ubicación**: .github/workflows/test.yml, línea 55

**Código vulnerable**:
```yaml
uses: ./
```

</details>

<details>
<summary>Ocurrencia 6 - .github/workflows/all_tests.yaml</summary>

**Ubicación**: .github/workflows/all_tests.yaml, línea 26

**Código vulnerable**:
```yaml
uses: ./.github/workflows/exportable_workflow.yaml
```

</details>

<details>
<summary>Ocurrencia 7 - .github/workflows/all_tests.yaml</summary>

**Ubicación**: .github/workflows/all_tests.yaml, línea 33

**Código vulnerable**:
```yaml
uses: ./.github/workflows/exportable_workflow.yaml
```

</details>

<details>
<summary>Ocurrencia 8 - .github/workflows/all_tests.yaml</summary>

**Ubicación**: .github/workflows/all_tests.yaml, línea 40

**Código vulnerable**:
```yaml
uses: ./.github/workflows/exportable_workflow.yaml
```

</details>

<details>
<summary>Ocurrencia 9 - .github/workflows/all_tests.yaml</summary>

**Ubicación**: .github/workflows/all_tests.yaml, línea 49

**Código vulnerable**:
```yaml
uses: ./.github/workflows/exportable_workflow.yaml
```

</details>

<details>
<summary>Ocurrencia 10 - .github/workflows/env-exps.yml</summary>

**Ubicación**: .github/workflows/env-exps.yml, línea 20

**Código vulnerable**:
```yaml
uses: ./.github/workflows/test-deploy.yml
```

</details>

<details>
<summary>Ocurrencia 11 - .github/workflows/env-exps.yml</summary>

**Ubicación**: .github/workflows/env-exps.yml, línea 38

**Código vulnerable**:
```yaml
uses: ./.github/workflows/test-regressions.yml
```

</details>

<details>
<summary>Ocurrencia 12 - .github/workflows/env-exps.yml</summary>

**Ubicación**: .github/workflows/env-exps.yml, línea 56

**Código vulnerable**:
```yaml
uses: ./.github/workflows/test-regressions.yml
```

</details>

<details>
<summary>Ocurrencia 13 - .github/workflows/test.yml</summary>

**Ubicación**: .github/workflows/test.yml, línea 36

**Código vulnerable**:
```yaml
uses: ./
```

</details>

<details>
<summary>Ocurrencia 14 - .github/workflows/test.yml</summary>

**Ubicación**: .github/workflows/test.yml, línea 51

**Código vulnerable**:
```yaml
uses: ./
```

</details>

<details>
<summary>Ocurrencia 15 - .github/workflows/typo-checker.yml</summary>

**Ubicación**: .github/workflows/typo-checker.yml, línea 46

**Código vulnerable**:
```yaml
uses: crate-ci/typos@master
```

</details>

### Script Injection (1 ocurrencias)

**Descripción**: Script multilinea con posible inyección de parámetros no sanitizados

**Severidad**: Media

**Impacto Potencial**: Los scripts multilinea que utilizan valores de eventos de GitHub sin sanitizar son susceptibles a inyecciones de comandos, lo que podría permitir a un atacante ejecutar comandos arbitrarios en el contexto del workflow.

**Vector de Explotación**: Por ejemplo, si el script contiene algo como `echo ${{ github.event.inputs.message }}`, un atacante podría ingresar: `mensaje legítimo; rm -rf /` como input, lo que ejecutaría el comando destructivo después del comando echo.

**Recomendación General**: 
1. Sanitizar todos los inputs antes de usarlos en scripts
2. Usar comillas para encapsular valores: `echo "${{ github.event.inputs.message }}"`
3. Validar inputs contra un patrón esperado usando expresiones regulares o listas permitidas
4. Considerar usar una acción personalizada para procesar inputs en lugar de scripts shell

**Referencias y Recursos**:

- https://docs.github.com/es/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable
- https://securitylab.github.com/research/github-actions-untrusted-input/
- https://owasp.org/www-community/attacks/Command_Injection

#### Ocurrencias Específicas

<details>
<summary>Ocurrencia 1 - .github/workflows/typo-checker.yml</summary>

**Ubicación**: .github/workflows/typo-checker.yml, línea 38

**Código vulnerable**:
```yaml
github.event_name: ${{ github.event_name }}
```

</details>

## Recomendaciones Generales de Seguridad para GitHub Actions

### Principios Básicos de Seguridad

1. **Principio de mínimo privilegio**: Otorgar sólo los permisos estrictamente necesarios para cada workflow.
2. **Inmutabilidad de componentes**: Usar hashes SHA completos para acciones en lugar de tags o ramas que pueden cambiar.
3. **Validación de entradas**: Sanitizar y validar todas las entradas externas antes de usarlas.
4. **Segmentación**: Dividir workflows críticos en múltiples jobs con diferentes niveles de acceso.
5. **Protección de secretos**: Manejar los secretos adecuadamente sin exponerlos en logs o outputs.

### Mejores Prácticas Específicas

#### Permisos y Autenticación

```yaml
# Definir permisos explícitos y restrictivos
permissions:
  contents: read
  issues: write
  # Otros permisos específicos según necesidad
```

#### Uso Seguro de Acciones de Terceros

```yaml
# Usar SHA completo en lugar de versiones o ramas
uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675
```

#### Manejo Seguro de Inputs

```yaml
# Validar y sanitizar inputs
- name: Validate input
  run: |
    INPUT="${{ github.event.inputs.parameter }}"
    if [[ ! $INPUT =~ ^[a-zA-Z0-9_-]+$ ]]; then
      echo "Input validation failed"
      exit 1
    fi
    echo "Validated input: $INPUT"
```

#### GitHub Advanced Security (GHAS)

Considerar la activación de las siguientes características de GitHub Advanced Security:

1. **CodeQL Analysis**: Para detección automática de vulnerabilidades en el código.
2. **Secret Scanning**: Para detectar credenciales expuestas accidentalmente.
3. **Dependabot**: Para mantener actualizadas las dependencias y corregir vulnerabilidades.
4. **Code Scanning**: Para integrar con herramientas adicionales de análisis estático.

## Recursos Adicionales

- [GitHub Actions Security Hardening Guide](https://docs.github.com/es/actions/security-guides/security-hardening-for-github-actions)
- [GitHub Advanced Security Documentation](https://docs.github.com/es/github/getting-started-with-github/about-github-advanced-security)
- [GitHub Security Advisories](https://github.com/advisories)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
