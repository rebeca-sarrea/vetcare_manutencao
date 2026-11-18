<?php
require_once __DIR__.'/config/database.php';
if (session_status() === PHP_SESSION_NONE) session_start();

// Já autenticado? Vai direto para o painel.
if (!empty($_SESSION['usuario_id'])) {
    header('Location: index.php'); exit;
}

// Token CSRF
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

// Hash "falso" usado para gastar o mesmo tempo quando o usuário não existe
// (evita descobrir contas válidas pelo tempo de resposta).
const HASH_FALSO = '$2y$10$u/J/T4jd7dVVIk7duTkbSuh6l5U/u0L/JPIlJ2d4Wh.N.SB8N.dk6';

const MAX_TENTATIVAS = 5;
const BLOQUEIO_SEGUNDOS = 300;

$erro = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $usuario = trim($_POST['usuario'] ?? '');
    $senha   = $_POST['senha'] ?? '';
    $token   = $_POST['csrf'] ?? '';

    $tentativas = $_SESSION['login_tentativas'] ?? 0;
    $ultima     = $_SESSION['login_ultima'] ?? 0;

    if ($tentativas >= MAX_TENTATIVAS && (time() - $ultima) < BLOQUEIO_SEGUNDOS) {
        $erro = 'Muitas tentativas. Aguarde alguns minutos e tente novamente.';
    } elseif (!hash_equals($_SESSION['csrf'], $token)) {
        $erro = 'Sessão expirada. Recarregue a página e tente novamente.';
    } else {
        if ($tentativas >= MAX_TENTATIVAS) { $tentativas = 0; } // bloqueio expirou

        $stmt = $pdo->prepare("SELECT id, nome, senha FROM usuarios WHERE usuario = ?");
        $stmt->execute([$usuario]);
        $conta = $stmt->fetch();

        // F01: sempre executa password_verify e devolve mensagem única
        $hash = $conta['senha'] ?? HASH_FALSO;
        $ok   = password_verify($senha, $hash) && $conta;

        if (!$ok) {
            $_SESSION['login_tentativas'] = $tentativas + 1;
            $_SESSION['login_ultima']     = time();
            $erro = 'Usuário ou senha inválidos.';
        } else {
            // Atualiza o hash se o algoritmo/custo padrão mudou
            if (password_needs_rehash($conta['senha'], PASSWORD_DEFAULT)) {
                $up = $pdo->prepare("UPDATE usuarios SET senha = ? WHERE id = ?");
                $up->execute([password_hash($senha, PASSWORD_DEFAULT), $conta['id']]);
            }

            // F02: regenera o ID da sessão após autenticar (anti session fixation)
            session_regenerate_id(true);
            unset($_SESSION['login_tentativas'], $_SESSION['login_ultima']);
            $_SESSION['csrf']         = bin2hex(random_bytes(32));
            $_SESSION['usuario_id']   = $conta['id'];
            $_SESSION['usuario_nome'] = $conta['nome'];
            header('Location: index.php'); exit;
        }
    }
}

$titulo = 'Entrar';
include __DIR__.'/includes/header.php';
?>
<div class="login-box"><h1>🐾 VetCare</h1><p class="muted">Acesse o sistema da clínica.</p>
<?php if ($erro): ?><div class="alert"><?= htmlspecialchars($erro) ?></div><?php endif; ?>
<form method="post" autocomplete="off">
  <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">
  <div class="field"><label>Usuário</label><input name="usuario" value="<?= htmlspecialchars($usuario ?? '') ?>" required autofocus></div>
  <div class="field"><label>Senha</label><input type="password" name="senha" required></div>
  <button type="submit">Entrar</button>
</form>
</div>
<?php include __DIR__.'/includes/footer.php'; ?>
