(define (domain dominio_teste_intrusao)
  (:requirements :typing :fluents)
  (:types 
    aplicacao
    estado
    injecao_sql
    xss 
    exploit
  )

  (:predicates
    (estado ?s - estado)
    (conexao_estados ?s1 ?s2 - estado)
    (autenticacao_obtida ?ast - aplicacao)
    (crawler_executado ?ast - aplicacao)
    (varredura_executada ?ast - aplicacao)
    (exploracao_executada ?ast - aplicacao)
    (tem_autenticacao ?ast - aplicacao)
    (teste_injecao_sql ?v - injecao_sql)
    (teste_xss ?v - xss)
    (executa_exploit ?e - exploit)		      
  )

  (:functions (prioridade))

  ;Aut1
  (:action info_autenticacao_wapiti
    :parameters   (?ast - aplicacao)
    :precondition (and (not(crawler_executado ?ast))
                       (not(varredura_executada ?ast))
                       (not(exploracao_executada ?ast))
                       (tem_autenticacao ?ast))
   
    :effect       (and (autenticacao_obtida ?ast))	
  ) 

  ;Cr1
  (:action crawler_htcap_sem_autenticacao
    :parameters   (?ast - aplicacao 
                   ?atual - estado ?proximo - estado)
    :precondition (and (estado ?atual)
                       (conexao_estados ?atual ?proximo)
                       (not(crawler_executado ?ast))
                       (not(varredura_executada ?ast))
                       (not(exploracao_executada ?ast))
                       (not(tem_autenticacao ?ast)))
   
    :effect       (and (estado ?proximo)
                       (not(estado ?atual))
                       (crawler_executado ?ast))
  ) 

  ;Cr2
  (:action crawler_htcap_com_autenticacao
    :parameters   (?ast - aplicacao
                   ?atual - estado ?proximo - estado)
    :precondition (and (estado ?atual)
                       (conexao_estados ?atual ?proximo)
                       (not(crawler_executado ?ast))
                       (not(varredura_executada ?ast))
                       (not(exploracao_executada ?ast))
                       (tem_autenticacao ?ast)
                       (autenticacao_obtida ?ast))
   
    :effect       (and (estado ?proximo)
                       (not(estado ?atual))
                       (crawler_executado ?ast))
  ) 

  ;Varr1
  (:action varredura_skipfish_sem_autenticacao
    :parameters   (?ast - aplicacao 
                   ?atual - estado ?proximo - estado)
    :precondition (and (estado ?atual)
                       (conexao_estados ?atual ?proximo)
                       (crawler_executado ?ast)
                       (not(varredura_executada ?ast))
                       (not(exploracao_executada ?ast))
                       (not(tem_autenticacao ?ast)))
   
    :effect       (and (estado ?proximo)
                       (not(estado ?atual))
                       (varredura_executada ?ast)
                       (increase (prioridade) 3))
  ) 
 
  ;Varr2
  (:action varredura_arachni_sem_autenticacao
    :parameters   (?ast - aplicacao 
                   ?atual - estado ?proximo - estado)
    :precondition (and (estado ?atual)
                       (conexao_estados ?atual ?proximo)
                       (crawler_executado ?ast)
                       (not(varredura_executada ?ast))
                       (not(exploracao_executada ?ast))
                       (not(tem_autenticacao ?ast)))
			
    :effect       (and (estado ?proximo)
                       (not(estado ?atual))
                       (varredura_executada ?ast)
                       (increase (prioridade) 2))
  ) 

  ;Varr3
  (:action varredura_zap_sem_autenticacao
    :parameters   (?ast - aplicacao 
                   ?atual - estado ?proximo - estado)
    :precondition (and (estado ?atual)
                       (conexao_estados ?atual ?proximo)
                       (crawler_executado ?ast)
                       (not(varredura_executada ?ast))
                       (not(exploracao_executada ?ast))
                       (not(tem_autenticacao ?ast)))
   
    :effect       (and (estado ?proximo)
                       (not(estado ?atual))
                       (varredura_executada ?ast)
                       (increase (prioridade) 1))  
  )  

  ;Varr4
  (:action varredura_skipfish_com_autenticacao
    :parameters   (?ast - aplicacao 
                   ?atual - estado ?proximo - estado)
    :precondition (and (estado ?atual)
                       (conexao_estados ?atual ?proximo)
                       (crawler_executado ?ast)
                       (not(varredura_executada ?ast))
                       (not(exploracao_executada ?ast))
                       (tem_autenticacao ?ast)
                       (autenticacao_obtida ?ast))            
   
    :effect       (and (estado ?proximo)
                       (not(estado ?atual))
                       (varredura_executada ?ast)
                       (increase (prioridade) 3))
  ) 

  ;Varr5
  (:action varredura_arachni_com_autenticacao
    :parameters   (?ast - aplicacao 
                   ?atual - estado ?proximo - estado)
    :precondition (and (estado ?atual)
                       (conexao_estados ?atual ?proximo)
                       (crawler_executado ?ast)
                       (not(varredura_executada ?ast))
                       (not(exploracao_executada ?ast))
   	                   (tem_autenticacao ?ast)
                       (autenticacao_obtida ?ast))            
   
    :effect       (and (estado ?proximo)
                       (not(estado ?atual))
                       (varredura_executada ?ast)
                       (increase (prioridade) 2))
  ) 

  ;Varr6
  (:action varredura_zap_com_autenticacao
    :parameters   (?ast - aplicacao 
                   ?atual - estado ?proximo - estado)
    :precondition (and (estado ?atual)
                       (conexao_estados ?atual ?proximo)
                       (crawler_executado ?ast)
                       (not(varredura_executada ?ast))
                       (not(exploracao_executada ?ast))
   	                   (tem_autenticacao ?ast)
                       (autenticacao_obtida ?ast))            
   
    :effect       (and (estado ?proximo)
                       (not(estado ?atual))
                       (varredura_executada ?ast)
                       (increase (prioridade) 1))
  ) 
  
  ;Exp1
  (:action exploracao_sqlmap_sem_autenticacao
    :parameters   (?v - injecao_sql ?ast - aplicacao 
                   ?atual - estado ?proximo - estado)
    :precondition (and (estado ?atual)
                       (conexao_estados ?atual ?proximo)
                       (crawler_executado ?ast)
                       (varredura_executada ?ast)
                       (not(exploracao_executada ?ast))
                       (not(tem_autenticacao ?ast))
                       (teste_injecao_sql ?v))

    :effect       (and (estado ?proximo)
                       (not(estado ?atual))
                       (exploracao_executada ?ast))
  ) 

  ;Exp2
  (:action exploracao_xsser_sem_autenticacao
    :parameters   (?v - xss ?ast - aplicacao 
                   ?atual - estado ?proximo - estado)
    :precondition (and (estado ?atual)
                       (conexao_estados ?atual ?proximo)
                       (crawler_executado ?ast)
                       (varredura_executada ?ast)
                       (not(exploracao_executada ?ast))
                       (not(tem_autenticacao ?ast))
                       (teste_xss ?v))

    :effect       (and (estado ?proximo)
                       (not(estado ?atual))
                       (exploracao_executada ?ast))
  ) 

  ;Exp3
  (:action exploracao_sqlmap_com_autenticacao
    :parameters   (?v - injecao_sql ?ast - aplicacao 
                   ?atual - estado ?proximo - estado)
    :precondition (and (estado ?atual)
                       (conexao_estados ?atual ?proximo)
                       (crawler_executado ?ast)
                       (varredura_executada ?ast)
                       (not(exploracao_executada ?ast))
                       (tem_autenticacao ?ast)
                       (autenticacao_obtida ?ast)
                       (teste_injecao_sql ?v))

    :effect       (and (estado ?proximo)
                       (not(estado ?atual))                      
                       (exploracao_executada ?ast))
  ) 

  ;Exp4
  (:action exploracao_xsser_com_autenticacao
    :parameters   (?v - xss ?ast - aplicacao 
                   ?atual - estado ?proximo - estado)
    :precondition (and (estado ?atual)
                       (conexao_estados ?atual ?proximo)
                       (crawler_executado ?ast)
                       (varredura_executada ?ast)
                       (not(exploracao_executada ?ast))
                       (tem_autenticacao ?ast)
                       (autenticacao_obtida ?ast)
                       (teste_xss ?v))

    :effect       (and (estado ?proximo)
                       (not(estado ?atual))                      
                       (exploracao_executada ?ast))
  ) 

  ;Frw1
  (:action exploracao_metasploit_exploit
    :parameters   (?e - exploit ?ast - aplicacao 
                   ?atual - estado ?proximo - estado)
    :precondition (and (estado ?atual)
                       (conexao_estados ?atual ?proximo)
                       (crawler_executado ?ast)
                       (varredura_executada ?ast)
                       (not(exploracao_executada ?ast))
                       (executa_exploit ?e))

    :effect       (and (estado ?proximo)
                       (not(estado ?atual))                      
                       (exploracao_executada ?ast))
  )

)
