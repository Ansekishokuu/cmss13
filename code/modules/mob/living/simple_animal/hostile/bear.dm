//Space bears!
/mob/living/simple_animal/hostile/bear
	name = "space bear"
	desc = "RawrRawr!!"
	icon_state = "bear"
	icon_living = "bear"
	icon_dead = "bear_dead"
	icon_gib = "bear_gib"
	speak = list("RAWR!","Rawr!","GRR!","Growl!")
	speak_emote = list("growls", "roars")
	emote_hear = list("rawrs","grumbles","grawls")
	emote_see = list("stares ferociously", "stomps")
	speak_chance = 1
	turns_per_move = 5
	see_in_dark = 6
	meat_type = /obj/item/reagent_container/food/snacks/bearmeat
	response_help  = "pets the"
	response_disarm = "gently pushes aside the"
	response_harm   = "pokes the"
	stop_automated_movement_when_pulled = 0
	maxHealth = 60
	health = 60
	melee_damage_lower = 20
	melee_damage_upper = 30

	//Space bears aren't affected by atmos.
	min_oxy = 0
	max_oxy = 0
	min_tox = 0
	max_tox = 0
	min_co2 = 0
	max_co2 = 0
	min_n2 = 0
	max_n2 = 0
	minbodytemp = 0
	var/stance_step = 0

	faction = FACTION_UPP

//SPACE BEARS! SQUEEEEEEEE~  OW! FUCK! IT BIT MY HAND OFF!!
/mob/living/simple_animal/hostile/bear/Hudson
	name = "Hudson"
	desc = ""
	response_help  = "pets"
	response_disarm = "gently pushes aside"
	response_harm   = "pokes"

/mob/living/simple_animal/hostile/bear/Life(delta_time)
	. = ..()
	if(!.)
		return

	if(loc && istype(loc,/turf/open/space))
		icon_state = "bear"
	else
		icon_state = "bearfloor"

	var/mob/living/target_mob = target_mob_ref?.resolve()

	switch(stance)

		if(HOSTILE_STANCE_TIRED)
			stop_automated_movement = 1
			stance_step++
			if(stance_step >= 10) //rests for 10 ticks
				if(target_mob && (target_mob in ListTargets(10)))
					stance = HOSTILE_STANCE_ATTACK //If the mob he was chasing is still nearby, resume the attack, otherwise go idle.
				else
					stance = HOSTILE_STANCE_IDLE

		if(HOSTILE_STANCE_ALERT)
			stop_automated_movement = 1
			var/found_mob = 0
			if(target_mob && (target_mob in ListTargets(10)))
				if(!(SA_attackable(target_mob)))
					stance_step = max(0, stance_step) //If we have not seen a mob in a while, the stance_step will be negative, we need to reset it to 0 as soon as we see a mob again.
					stance_step++
					found_mob = 1
					src.setDir(get_dir(src,target_mob)) //Keep staring at the mob

					if(stance_step in list(1,4,7)) //every 3 ticks
						var/action = pick( list( "growls at [target_mob]", "stares angrily at [target_mob]", "prepares to attack [target_mob]", "closely watches [target_mob]" ) )
						if(action)
							INVOKE_ASYNC(src, PROC_REF(manual_emote), action)
			if(!found_mob)
				stance_step--

			if(stance_step <= -20) //If we have not found a mob for 20-ish ticks, revert to idle mode
				stance = HOSTILE_STANCE_IDLE
			if(stance_step >= 7)   //If we have been staring at a mob for 7 ticks,
				stance = HOSTILE_STANCE_ATTACK

		if(HOSTILE_STANCE_ATTACKING)
			if(stance_step >= 20) //attacks for 20 ticks, then it gets tired and needs to rest
				INVOKE_ASYNC(src, PROC_REF(manual_emote), "is worn out and needs to rest")
				stance = HOSTILE_STANCE_TIRED
				stance_step = 0
				walk(src, 0) //This stops the bear's walking
				return



/mob/living/simple_animal/hostile/bear/attackby(obj/item/O as obj, mob/user as mob)
	if(stance != HOSTILE_STANCE_ATTACK && stance != HOSTILE_STANCE_ATTACKING)
		stance = HOSTILE_STANCE_ALERT
		stance_step = 6
		target_mob_ref = WEAKREF(user)
	return ..()

/mob/living/simple_animal/hostile/bear/attack_hand(mob/living/carbon/human/attacking_mob)
	if(stance != HOSTILE_STANCE_ATTACK && stance != HOSTILE_STANCE_ATTACKING)
		stance = HOSTILE_STANCE_ALERT
		stance_step = 6
		target_mob_ref = WEAKREF(attacking_mob)
	return ..()

/mob/living/simple_animal/hostile/bear/Process_Spacemove(check_drift = 0)
	return //No drifting in space for space bears!

/mob/living/simple_animal/hostile/bear/FindTarget()
	. = ..()
	if(.)
		manual_emote("stares alertly at [.]")
		stance = HOSTILE_STANCE_ALERT

/mob/living/simple_animal/hostile/bear/LoseTarget()
	..(5)

/mob/living/simple_animal/hostile/bear/AttackingTarget()
	var/mob/living/target_mob = target_mob_ref?.resolve()
	if(!Adjacent(target_mob))
		return
	manual_emote(pick(list("slashes at [target_mob]", "bites [target_mob]")))

	var/damage = rand(20,30)

	if(ishuman(target_mob))
		var/mob/living/carbon/human/hooman = target_mob
		var/dam_zone = pick("chest", "l_hand", "r_hand", "l_leg", "r_leg")
		var/obj/limb/affecting = hooman.get_limb(rand_zone(dam_zone))
		hooman.apply_damage(damage, BRUTE, affecting, sharp=1, edge=1)
		return hooman
	else if(isliving(target_mob))
		target_mob.apply_damage(damage, BRUTE)
		return target_mob

























