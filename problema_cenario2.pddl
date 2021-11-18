;problema_cenario2.pddl

(define (problem problema_cenario2_injecao_sql)
  (:domain dominio_teste_intrusao)
  (:objects ast-com-autenticacao - aplicacao
            injecao_sql - injecao_sql
            xss - xss
            exploit - exploit
            ei int1 int2 ef - estado)
  (:init
          (estado ei)
          (conexao_estados ei int1)
          (conexao_estados int1 int2)
          (conexao_estados int2 ef)
          (tem_autenticacao ast-com-autenticacao)
          (teste_injecao_sql injecao_sql)
          (= (prioridade) 0))
          
  (:goal  (and (estado ef)))
  (:metric minimize (prioridade))	
)
