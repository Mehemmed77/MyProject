# Generated by Django 4.0.6 on 2022-07-31 18:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_alter_user_email'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='image',
            field=models.ImageField(default='profile-pictures/default.jpg', upload_to='profile-pictures/'),
        ),
    ]
