# Fase 0 — Higiene de la cuenta AWS

**Objetivo:** dejar la cuenta segura y con un límite de gasto vigilado **antes**
de crear ningún recurso. Todo es manual (consola), porque es lo que tiene que
existir antes de que haya Terraform.

**Resultado verificable:**

- [x] MFA activo en el usuario root y sin access keys de root.
- [x] Plan de la cuenta confirmado (Free / Paid) y fecha de caducidad de los créditos apuntada.
- [x] Budget mensual de 5 $ con aviso por email.
- [x] Usuario de trabajo en IAM Identity Center, con MFA.
- [x] `aws sts get-caller-identity --profile personal` devuelve la cuenta personal.

## Antes de empezar: una cuenta, un perfil

Si en el PC hay credenciales de otra cuenta (por ejemplo, la del trabajo) en el
perfil `default`, cualquier `aws` o `terraform` sin `--profile` iría contra
ella. Este proyecto usa **siempre un perfil con nombre** (`personal`) y nunca
`default`, así que un comando sin perfil falla en vez de tocar otra cuenta.

Comprobación antes de cualquier operación:

```bash
aws sts get-caller-identity --profile personal
```

## 1. MFA en root

Por qué: root puede hacer cualquier cosa (cerrar la cuenta, cambiar el pago) y
ninguna política IAM lo limita. Con solo su contraseña, la cuenta es de quien
la tenga.

- Menú de la cuenta (arriba a la derecha) → *Security credentials* → *Assign MFA device*.
- Comprobar que no hay *access keys* de root. Root no debe tener claves nunca.
- Después de esto, root solo se usa para lo que exige root (pago, cerrar la cuenta).

## 2. Plan de la cuenta y créditos

Por qué: desde julio de 2025, las cuentas nuevas eligen entre *Free plan* y
*Paid plan*. El Free plan se cierra solo al acabar (6 meses o al agotar los
créditos) si no se pasa al de pago, y a los 90 días se borra todo. Para un
proyecto que tiene que seguir vivo, eso importa.

- Menú de la cuenta → *Account*: ver el plan.
- *Billing and Cost Management* → *Credits*: saldo y fecha de caducidad.

## 3. Budget

Por qué: es la red de seguridad. Un error de Terraform (una NAT Gateway, una
instancia olvidada) se nota en el email antes que en la factura. Lo previsto
para este proyecto cuesta céntimos al mes, así que 5 $ deja margen y salta
ante cualquier sorpresa.

- *Billing and Cost Management* → *Budgets* → *Create budget* → plantilla
  *Monthly cost budget*, 5 $, email propio.
- Avisos: 85 % del gasto real y 100 % del previsto.

## 4. IAM Identity Center (usuario de trabajo)

Por qué: en vez de un usuario IAM con claves de acceso de larga duración
guardadas en el PC (si se filtran, valen hasta que alguien las revoque), se
entra con `aws sso login` y se obtienen **credenciales temporales** (8 h). Con
MFA y sin nada permanente en disco.

- Activar IAM Identity Center (región `eu-south-2`). Esto crea una
  organización de AWS Organizations con la cuenta como cuenta de gestión.
  - **Instance configuration → Single-Region instance** (Europe (Spain)). La
    opción multirregión cifra con claves KMS gestionadas por el cliente
    (~1 $/mes por clave, una por región: casi la mitad del budget) para
    replicar el acceso a otra región, algo que una cuenta personal no
    necesita (si cae la región, queda root). Single-Region cifra con una
    clave propiedad de AWS, sin coste. La región principal **no se puede
    cambiar después**.
- *Users* → crear usuario propio.
- *Permission sets* → `AdministratorAccess`, sesión de 8 h.
- *AWS accounts* → asignar usuario + permission set a la cuenta.
- Primer inicio de sesión en la *AWS access portal URL*: activar el MFA del usuario.

## 5. CLI con SSO

```bash
aws configure sso --profile personal
# SSO start URL: la AWS access portal URL del paso 4
# SSO region: eu-south-2
# Región por defecto: eu-south-2, salida: json

aws sso login --profile personal                # cada vez que caduque la sesión
aws sts get-caller-identity --profile personal  # comprobación
```

## Notas y decisiones

- Región del proyecto: `eu-south-2` (España).
- Nada de esta fase vive en Terraform: es la base sobre la que se ejecuta
  Terraform. El budget podría importarse a Terraform más adelante.

## Verificación (2026-10-22)

Todo comprobado desde la CLI, con consultas de solo lectura:

```bash
P="--profile personal"
aws sts get-caller-identity $P                                  # cuenta personal, rol AWSReservedSSO_AdministratorAccess_*
aws iam get-account-summary $P \
  --query "SummaryMap.{RootMFA:AccountMFAEnabled,RootKeys:AccountAccessKeysPresent}"   # 1 y 0
aws budgets describe-budgets $P --account-id <id>              # 5 USD/mes
aws freetier get-account-plan-state $P --region us-east-1      # accountPlanType: PAID
```

- Plan **Paid**: la cuenta no se cierra sola al acabar los créditos.
- `accountPlanRemainingCredits` sale a 0 aunque la página *Credits* muestra
  los 100 $ de bienvenida: ese campo parece contar solo créditos del Free plan.
- La cuenta no tenía recursos (ni buckets ni instancias): punto de partida limpio.
