#JavaScript
<script>
    (function(){
        if('{{ page.password }}'){
            if (prompt('请输入密码') !== '{{ page.password }}'){
                alert('密码错误');
                history.back();
            }
        }
    })();
</script>
